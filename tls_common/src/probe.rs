use anyhow::{anyhow, Context, Result};
use hkdf::Hkdf;
use sha2::{Sha256, Sha384};
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, aead::{AeadInPlace, generic_array::GenericArray}};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit as ChachaKeyInit, aead::{AeadInPlace as ChachaAeadInPlace, generic_array::GenericArray as ChachaGA}};
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

#[derive(Debug, Clone)]
pub struct NegotiatedParams {
    pub cipher_suite: String,                     // 例如 TLS_AES_128_GCM_SHA256
    pub named_group: String,                      // 例如 x25519
    pub signature_algorithm: Option<String>,      // 例如 ecdsa_secp256r1_sha256
    pub certificate_der: Option<Vec<u8>>,         // 叶子证书 DER
    pub ec_curve_oid: Option<String>,             // 证书里声明的 EC 曲线 OID（若有）
    pub ec_pubkey_uncompressed_hex: Option<String>, // 证书 EC 公钥未压缩点（04|X|Y）
}

fn be_u16(b: &[u8]) -> u16 { u16::from_be_bytes([b[0], b[1]]) }
fn be_u24(b: &[u8]) -> usize { ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | (b[2] as usize) }

#[derive(Clone, Copy)] enum AeadKind { Aes128Gcm, Aes256Gcm, ChaCha20Poly1305 }
#[derive(Clone, Copy)] enum HashKind { Sha256, Sha384 }

fn cipher_name(id: u16) -> Option<(&'static str, AeadKind, HashKind, usize)> {
    match id {
        0x1301 => Some(("TLS_AES_128_GCM_SHA256", AeadKind::Aes128Gcm, HashKind::Sha256, 16)),
        0x1302 => Some(("TLS_AES_256_GCM_SHA384", AeadKind::Aes256Gcm, HashKind::Sha384, 32)),
        0x1303 => Some(("TLS_CHACHA20_POLY1305_SHA256", AeadKind::ChaCha20Poly1305, HashKind::Sha256, 32)),
        _ => None,
    }
}
fn group_name(id: u16) -> &'static str {
    match id { 0x001D=>"x25519",0x0017=>"secp256r1",0x0018=>"secp384r1",0x0019=>"secp521r1",
               0x0101=>"ffdhe2048",0x0102=>"ffdhe3072",0x0103=>"ffdhe4096", _=>"unknown" }
}
fn sigscheme_name(id: u16) -> &'static str {
    match id {
        0x0403=>"ecdsa_secp256r1_sha256",0x0503=>"ecdsa_secp384r1_sha384",0x0603=>"ecdsa_secp521r1_sha512",
        0x0804=>"rsa_pss_rsae_sha256",0x0805=>"rsa_pss_rsae_sha384",0x0806=>"rsa_pss_rsae_sha512",
        0x0807=>"ed25519",0x0808=>"ed448",
        0x0401=>"rsa_pkcs1_sha256",0x0501=>"rsa_pkcs1_sha384",0x0601=>"rsa_pkcs1_sha512",
        _=>"unknown"
    }
}

fn hkdf_expand_label(secret: &[u8], label: &str, len: usize, hash: HashKind) -> Vec<u8> {
    // HKDF-Expand-Label(secret, "tls13 " + label, "", len)
    let full = format!("tls13 {}", label);
    let mut info = Vec::with_capacity(2 + 1 + full.len() + 1);
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(0u8); // context = empty
    match hash {
        HashKind::Sha256 => { let hk = Hkdf::<Sha256>::from_prk(secret).expect("prk");
            let mut out = vec![0u8; len]; hk.expand(&info, &mut out).expect("expand"); out }
        HashKind::Sha384 => { let hk = Hkdf::<Sha384>::from_prk(secret).expect("prk");
            let mut out = vec![0u8; len]; hk.expand(&info, &mut out).expect("expand"); out }
    }
}

fn make_nonce(static_iv: &[u8;12], seq: u64) -> [u8;12] {
    let mut n = *static_iv;
    let s = seq.to_be_bytes();
    for i in 0..8 { n[12-8+i] ^= s[i]; }
    n
}

fn split_tls_records(buf: &[u8]) -> Vec<&[u8]> {
    let mut recs = Vec::new(); let mut off = 0usize;
    while off + 5 <= buf.len() {
        let typ = buf[off]; let len = be_u16(&buf[off+3..off+5]) as usize;
        if off + 5 + len > buf.len() { break; }
        if matches!(typ, 0x14 | 0x16 | 0x17) { recs.push(&buf[off..off+5+len]); }
        off += 5 + len;
    } recs
}

/// 从客户端->服务端（rx）流里找到 ClientHello 并取 client_random
pub fn extract_client_random_from_tx(tx: &[u8]) -> Result<[u8;32]> {
    for r in split_tls_records(tx) {
        if r[0] != 0x16 { continue; }                     // Handshake
        let hs = &r[5..];
        if hs.len() < 4 || hs[0] != 0x01 { continue; }    // ClientHello
        let bl = be_u24(&hs[1..4]); if hs.len() < 4+bl { continue; }
        let body=&hs[4..4+bl];
        if body.len() < 34 { continue; }
        let mut rand=[0u8;32]; rand.copy_from_slice(&body[2..34]); return Ok(rand);
    }
    Err(anyhow!("ClientHello not found in tx"))
}

/// 从服务端->客户端（tx）流里解析 ServerHello，取 cipher_suite、selected_group，并返回该记录末尾偏移
pub fn parse_server_hello_from_rx(rx: &[u8]) -> Result<(u16, Option<u16>, usize)> {
    let recs = split_tls_records(rx); let mut end_off=0usize;
    for r in recs {
        end_off += r.len();
        if r[0]!=0x16 { continue; }
        let hs=&r[5..]; if hs.len()<4 || hs[0]!=0x02 { continue; } // ServerHello
        let bl = be_u24(&hs[1..4]); if hs.len() < 4+bl { continue; }
        let mut p=4;
        p += 2+32;                                 // legacy_version + random
        if hs.len() < p+1 { continue; }
        let sid_len=hs[p] as usize; p+=1; p+=sid_len;
        if hs.len() < p+2+1+2 { continue; }
        let cipher = be_u16(&hs[p..p+2]); p+=2;
        let _compression = hs[p]; p+=1;
        let _ext_len = be_u16(&hs[p..p+2]) as usize; p+=2;

        let mut selected_group=None; let mut q=p;
        while q+4 <= 4+bl {
            let et=be_u16(&hs[q..q+2]); q+=2;
            let el=be_u16(&hs[q..q+2]) as usize; q+=2;
            if q+el > 4+bl { break; }
            if et==0x0033 && el>=2 { selected_group=Some(be_u16(&hs[q..q+2])); } // key_share / selected_group
            q+=el;
        }
        return Ok((cipher, selected_group, end_off));
    }
    Err(anyhow!("ServerHello not found in rx"))
}

/// 从 KeyLog 行找到指定 label+client_random 的 secret（hex -> bytes）
pub fn find_secret_from_keylog(lines: &[String], label: &str, client_random:&[u8;32]) -> Result<Vec<u8>> {
    let cr_hex = hex::encode_upper(client_random);
    for line in lines {
        let mut it = line.split_whitespace();
        if let (Some(lab), Some(cr), Some(sec)) = (it.next(), it.next(), it.next()) {
            if lab==label && cr.eq_ignore_ascii_case(&cr_hex) {
                return Ok(hex::decode(sec).map_err(|e| anyhow!("hex decode: {}", e))?);
            }
        }
    }
    Err(anyhow!("secret {} for client_random not found", label))
}

struct AeadKeys { aead: AeadKind, hash: HashKind, key: Vec<u8>, iv: [u8;12] }
fn derive_server_handshake_keys(suite: u16, server_hs_secret: &[u8]) -> Result<AeadKeys> {
    let (_name, aead, hash, klen) = cipher_name(suite).ok_or_else(|| anyhow!("unsupported suite {:04x}", suite))?;
    let key = hkdf_expand_label(server_hs_secret, "key", klen, hash);
    let ivv = hkdf_expand_label(server_hs_secret, "iv", 12, hash);
    let mut iv = [0u8;12]; iv.copy_from_slice(&ivv);
    Ok(AeadKeys { aead, hash, key, iv })
}

/// 解密一条 0x17 记录，得到 TLSInnerPlaintext（去掉 padding + 末尾 content-type）
fn decrypt_appdata_record_to_handshake(aead:&AeadKeys, seq:&mut u64, rec:&[u8]) -> Result<Vec<u8>> {
    if rec[0]!=0x17 { return Err(anyhow!("not application_data record")); }
    let hdr=&rec[..5]; let ct=&rec[5..]; if ct.len()<16 { return Err(anyhow!("ciphertext too short")); }
    let nonce = make_nonce(&aead.iv, *seq); *seq += 1;

    let mut buf = ct.to_vec();
    match aead.aead {
        AeadKind::Aes128Gcm => {
            let c=Aes128Gcm::new(GenericArray::from_slice(&aead.key));
            let tag=buf.split_off(buf.len()-16);
            c.decrypt_in_place_detached(GenericArray::from_slice(&nonce), hdr, &mut buf, GenericArray::from_slice(&tag))
                .map_err(|_| anyhow!("AES-128-GCM decrypt failed"))?;
        }
        AeadKind::Aes256Gcm => {
            let c=Aes256Gcm::new(GenericArray::from_slice(&aead.key));
            let tag=buf.split_off(buf.len()-16);
            c.decrypt_in_place_detached(GenericArray::from_slice(&nonce), hdr, &mut buf, GenericArray::from_slice(&tag))
                .map_err(|_| anyhow!("AES-256-GCM decrypt failed"))?;
        }
        AeadKind::ChaCha20Poly1305 => {
            let c=ChaCha20Poly1305::new(ChachaGA::from_slice(&aead.key));
            let tag=buf.split_off(buf.len()-16);
            c.decrypt_in_place_detached(ChachaGA::from_slice(&nonce), hdr, &mut buf, ChachaGA::from_slice(&tag))
                .map_err(|_| anyhow!("ChaCha20-Poly1305 decrypt failed"))?;
        }
    }
    if buf.is_empty() { return Err(anyhow!("inner plaintext empty")); }
    // TLSInnerPlaintext = content || 0x16 (Handshake) || padding(0x00..)
    let mut i = buf.len()-1;
    let ctype = buf[i];
    if ctype != 0x16 { return Err(anyhow!("inner content-type != Handshake(0x16), got {:02x}", ctype)); }
    while i > 0 && buf[i-1]==0x00 { i -= 1; }
    buf.truncate(i);
    Ok(buf)
}

/// 从 ServerHello 之后的（server->client）字节流中，累积解密出握手明文
pub fn decrypt_server_handshake_stream(rx_after_sh:&[u8], aead:&AeadKeys) -> Result<Vec<u8>> {
    let mut seq: u64 = 0;
    let mut out = Vec::new();
    let mut saw_finished = false; // ← 别忘了定义

    for rec in split_tls_records(rx_after_sh) {
        match rec[0] {
            0x14 => { /* TLS 1.3 里可能有明文 CCS，忽略 */ }
            0x17 => {
                // 尝试用“握手密钥”解；失败通常意味着已经切到“应用密钥”，直接停止
                match decrypt_appdata_record_to_handshake(aead, &mut seq, rec) {
                    Ok(inner) => {
                        out.extend_from_slice(&inner);

                        // 扫描这条记录里的握手消息是否包含 Finished(0x14)
                        let mut s = inner.as_slice();
                        while s.len() >= 4 {
                            let typ = s[0];
                            let len = be_u24(&s[1..4]);
                            if s.len() < 4 + len { break; }
                            if typ == 0x14 { // Finished
                                saw_finished = true;
                                break;
                            }
                            s = &s[4 + len..];
                        }
                        if saw_finished { break; }
                    }
                    Err(_e) => {
                        // 第一条解不动，多半已经切到应用阶段，停止而不是报错
                        break;
                    }
                }
            }
            0x16 => { /* ServerHello 之后不应再出现明文握手 */ }
            _ => {}
        }
    }
    Ok(out)
}

/// 在连续的握手明文里提取 Certificate(叶子) 与 CertificateVerify 的签名算法
pub fn extract_cert_and_sigalg_from_handshake_stream(mut hs:&[u8]) -> Result<(Option<Vec<u8>>, Option<u16>)> {
    let mut cert_der: Option<Vec<u8>> = None;
    let mut sigalg:   Option<u16>     = None;

    while hs.len() >= 4 {
        let typ = hs[0];
        let len = be_u24(&hs[1..4]);
        if hs.len() < 4 + len { break; }
        let body = &hs[4..4+len];

        match typ {
            11 => { // Certificate
                if body.len() >= 1+3 {
                    let ctx_len = body[0] as usize;
                    let mut p = 1 + ctx_len;
                    if body.len() >= p+3 {
                        let _list_len = be_u24(&body[p..p+3]); p += 3;
                        if body.len() >= p+3 {
                            let cert_len = be_u24(&body[p..p+3]); p += 3;
                            if body.len() >= p + cert_len {
                                cert_der = Some(body[p..p+cert_len].to_vec());
                            }
                        }
                    }
                }
            }
            15 => { // CertificateVerify
                if body.len() >= 2 { sigalg = Some(be_u16(&body[0..2])); }
            }
            _ => {}
        }

        hs = &hs[4+len..];
        if cert_der.is_some() && sigalg.is_some() { break; }
    }

    Ok((cert_der, sigalg))
}

/// 解析证书中的 EC 公钥与曲线 OID（如 prime256v1）
pub fn parse_ec_from_cert(cert_der:&[u8]) -> (Option<String>, Option<String>) {
    if let Ok((_rem, cert)) = X509Certificate::from_der(cert_der) {
        // 证书声明的曲线：在 SPKI.algorithm.parameters (namedCurve OID)
        let spki = &cert.tbs_certificate.subject_pki;
        let curve_oid = spki.algorithm.parameters.as_ref()
            .and_then(|any| any.as_oid().ok())
            .map(|oid| oid.to_string()); // dotted string

        // EC 公钥未压缩点（04|X|Y）
        let ec_hex = match spki.parsed() {
            Ok(PublicKey::EC(ec)) => Some(hex::encode_upper(ec.data())),
            _ => None,
        };
        (curve_oid, ec_hex)
    } else {
        (None, None)
    }
}

/// 入口（服务端视角）
/// - rx: 客户端->服务端 的原始字节（含 ClientHello）
/// - tx: 服务端->客户端 的原始字节（含 ServerHello 与后续密文）
/// - keylog_lines: CollectKeyLog 收集的行
pub fn extract_params(rx:&[u8], tx:&[u8], keylog_lines:&[String]) -> Result<NegotiatedParams> {
    let client_random = extract_client_random_from_tx(rx).context("extract client_random")?;
    let (suite_id, group_opt, sh_end) = parse_server_hello_from_rx(tx).context("parse server_hello")?;
    let (suite_name, _aead, _hash, _klen) = cipher_name(suite_id).ok_or_else(|| anyhow!("unsupported cipher suite"))?;
    let named_group = group_opt.map(group_name).unwrap_or("unknown").to_string();

    // 用 SERVER_HANDSHAKE_TRAFFIC_SECRET 解密服务端->客户端握手
    let server_hs = find_secret_from_keylog(keylog_lines, "SERVER_HANDSHAKE_TRAFFIC_SECRET", &client_random)?;
    let aead_keys = derive_server_handshake_keys(suite_id, &server_hs)?;
    let hs_plain = decrypt_server_handshake_stream(&tx[sh_end..], &aead_keys).context("decrypt handshake")?;
    let (cert_der, sigalg) = extract_cert_and_sigalg_from_handshake_stream(&hs_plain)?;

    let (ec_curve_oid, ec_pub_hex) = if let Some(ref der) = cert_der {
        parse_ec_from_cert(der)
    } else { (None, None) };

    Ok(NegotiatedParams {
        cipher_suite: suite_name.to_string(),
        named_group,
        signature_algorithm: sigalg.map(sigscheme_name).map(|s| s.to_string()),
        certificate_der: cert_der,
        ec_curve_oid,
        ec_pubkey_uncompressed_hex: ec_pub_hex,
    })
}
