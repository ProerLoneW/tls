// tls_common/src/bin/cert_generator.rs

use clap::{Command, Arg, ArgMatches};
use std::path::Path;
use rcgen::{
    CertificateParams, DistinguishedName, KeyPair,
    IsCa, KeyUsagePurpose,
};

// <-- 引入 KeyPair
use std::fs;
use std::path::PathBuf;

// --- openssl 相关的 imports ---
use openssl::pkey::PKey;
// use openssl::rsa::Rsa;
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::x509::{X509, X509Builder, X509NameBuilder};
use openssl::x509::extension::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
};
use openssl::hash::MessageDigest;
use openssl::asn1::Asn1Time;
use rand;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("cert-generator")
        .version("1.0")
        .about("生成 TLS 证书")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("self-signed")
                .about("生成一个自签名的 CA 证书")
                .arg(Arg::new("ca-common-name")
                    .long("ca-common-name")
                    .help("自签名 CA 的通用名称 (CN)")
                    .default_value("My TLS CA"))
                .arg(Arg::new("out-cert")
                    .long("out-cert")
                    .help("输出证书文件的路径")
                    .required(true)
                    .value_parser(clap::value_parser!(PathBuf)))
                .arg(Arg::new("out-key")
                    .long("out-key")
                    .help("输出私钥文件的路径")
                    .required(true)
                    .value_parser(clap::value_parser!(PathBuf)))
        )
        .subcommand(
            Command::new("sign")
                .about("使用一个已有的 CA 来签发新证书")
                .arg(Arg::new("ca-name")
                    .long("ca-name")
                    .help("用于签名的 CA 名称 (会自动查找 <ca_name>.crt 和 <ca_name>.key)")
                    .required(true))
                .arg(Arg::new("out-cert")
                    .long("out-cert")
                    .help("输出证书文件的路径")
                    .required(true)
                    .value_parser(clap::value_parser!(PathBuf)))
                .arg(Arg::new("out-key")
                    .long("out-key")
                    .help("输出私钥文件的路径")
                    .required(true)
                    .value_parser(clap::value_parser!(PathBuf)))
                .arg(Arg::new("common-name").long("common-name").help("新证书的通用名称 (CN)"))
                .arg(Arg::new("dns-names").long("dns-names").help("逗号分隔的 DNS 名称 (SAN)"))
                .arg(Arg::new("ip-addresses").long("ip-addresses").help("逗号分隔的 IP 地址 (SAN)"))
                .arg(Arg::new("is-server").long("is-server").action(clap::ArgAction::SetTrue).help("标记为服务器认证证书"))
                .arg(Arg::new("is-client").long("is-client").action(clap::ArgAction::SetTrue).help("标记为客户端认证证书"))
        )
        .get_matches();

    match matches.subcommand() {
        Some(("self-signed", sub_matches)) => {
            let ca_common_name = sub_matches.get_one::<String>("ca-common-name").unwrap();
            let out_cert = sub_matches.get_one::<PathBuf>("out-cert").unwrap();
            let out_key = sub_matches.get_one::<PathBuf>("out-key").unwrap();
            
            ensure_dir_exists(out_cert)?;
            ensure_dir_exists(out_key)?;
            generate_self_signed_cert(ca_common_name, out_cert, out_key)?;
        }
        Some(("sign", sub_matches)) => {
            ensure_dir_exists(sub_matches.get_one::<PathBuf>("out-cert").unwrap())?;
            ensure_dir_exists(sub_matches.get_one::<PathBuf>("out-key").unwrap())?;
            generate_ca_signed_cert(sub_matches)?;
        }
        _ => unreachable!("因为设置了 subcommand_required(true)，所以不可能到这里"),
    }

    println!("\n🎉 证书和私钥已成功生成！");
    Ok(())
}

fn ensure_dir_exists(path: &Path) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

/// CA 自签名证书
fn generate_self_signed_cert(
    ca_common_name: &str,
    out_cert: &Path,
    out_key: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("⚙️ 模式: 生成自签名 CA 证书...");
    
    let mut params = CertificateParams::default();
    
    // 设置为 ca 证书
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    
    // 用途
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign, // 可以签署其他证书
        KeyUsagePurpose::CrlSign,     // 可以签署证书吊销列表
    ];

    let mut name = DistinguishedName::new();
    name.push(rcgen::DnType::CommonName, ca_common_name);
    name.push(rcgen::DnType::OrganizationName, "My TLS Project");
    name.push(rcgen::DnType::CountryName, "CN");
    params.distinguished_name = name;

    // 生成密钥对，默认使用 ECDSA-P256
    let keypair = KeyPair::generate().unwrap();
    
    // 自签名
    let cert = params.self_signed(&keypair)?;

    fs::write(out_cert, cert.pem())?;
    fs::write(out_key, keypair.serialize_pem())?;

    println!("生成了自签名 CA 证书：");
    println!("   - {}", out_cert.display());
    println!("   - {}", out_key.display());

    Ok(())
}

/// 使用 CA 签发证书
// fn generate_ca_signed_cert(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
//     // 1. 加载 CA 证书（PEM）和私钥（PEM）
//     let ca_cert_pem = fs::read_to_string(format!("{}.crt", args.ca_name))?;
//     let ca_key_pem = fs::read_to_string(format!("ca_key/{}.pem", args.ca_name))?;

//     // 2. 解析 CA 私钥
//     let ca_keypair = KeyPair::from_pem(&ca_key_pem)?;

//     // 3. 解析 CA 证书的 DER 数据
//     let ca_cert_der = CertificateDer::from_slice(ca_cert_pem.as_bytes())?;

//     // 4. ✅ 用 x509-parser 解析证书，提取 Common Name (CN)
//     let (_, x509) = parse_x509_certificate(ca_cert_der.as_ref())
//         .map_err(|_| "无法解析 CA 证书")?;
//     let ca_common_name = x509
//         .subject()
//         .iter_common_name()
//         .next()
//         .ok_or("CA 证书没有 Common Name")?
//         .as_str()
//         .map_err(|_| "Common Name 不是合法字符串")?;

//     // 5. ✅ 用 Common Name 和 KeyPair 构造 Issuer
//     let issuer = Issuer::new(ca_common_name, ca_keypair);

//     // 5. 构建要签发的证书参数
//     let mut params = CertificateParams::new(Vec::new())?;
//     params.is_ca = IsCa::NoCa;

//     // 6. 设置主题备用名称 (SAN)
//     if let Some(dns) = &args.dns_names {
//         for name in dns.split(',') {
//             params.subject_alt_names.push(SanType::DnsName(
//                 Ia5String::try_from(name.trim().to_string()).unwrap(),
//             ));
//         }
//     }
//     if let Some(ips) = &args.ip_addresses {
//         for ip in ips.split(',') {
//             params.subject_alt_names.push(SanType::IpAddress(ip.trim().parse()?));
//         }
//     }

//     // 7. 设置通用名称 (CN)
//     if let Some(cn) = &args.common_name {
//         let mut name = DistinguishedName::new();
//         name.push(DnType::CommonName, cn);
//         params.distinguished_name = name;
//     }

//     // 8. 设置密钥用途 (Key Usage)
//     params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
//     if args.is_server {
//         params.extended_key_usages.push(ExtendedKeyUsagePurpose::ServerAuth);
//     }
//     if args.is_client {
//         params.extended_key_usages.push(ExtendedKeyUsagePurpose::ClientAuth);
//     }

//     // 9. 生成新证书的密钥对
//     let keypair = KeyPair::generate().unwrap();

//     // 10. 用 CA 签发证书
//     let cert = params.signed_by(&keypair, &issuer)?;

//     // 11. 写入文件
//     fs::write(&args.out_cert, cert.pem())?;
//     fs::write(&args.out_key, keypair.serialize_pem())?;

//     println!("✅ 用 CA 签发了证书：");
//     println!("   - {}", args.out_cert.display());
//     println!("   - {}", args.out_key.display());

//     Ok(())
// }

/// 使用 openssl crate 和指定的 CA 签发新证书
fn generate_ca_signed_cert(args: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let ca_name = args.get_one::<String>("ca-name").unwrap();
    let out_cert = args.get_one::<PathBuf>("out-cert").unwrap();
    let out_key = args.get_one::<PathBuf>("out-key").unwrap();

    println!("⚙️ 模式: 使用 CA '{}' 签发新证书...", ca_name);

    // --- 1. 加载 CA 证书和私钥 ---
    let ca_cert_path = format!("{}.crt", ca_name);
    let ca_key_path = format!("./ca_key/{}.key", ca_name);
    
    println!("   - 读取 CA 证书: {}", ca_cert_path);
    println!("   - 读取 CA 私钥: {}", ca_key_path);

    let ca_cert_pem = fs::read(&ca_cert_path)
        .map_err(|e| format!("无法读取 CA 证书 '{}': {}", ca_cert_path, e))?;
    let ca_key_pem = fs::read(&ca_key_path)
        .map_err(|e| format!("无法读取 CA 私钥 '{}': {}", ca_key_path, e))?;

    let ca_cert = X509::from_pem(&ca_cert_pem)?;
    let ca_pkey = PKey::private_key_from_pem(&ca_key_pem)?;

    // --- 2. 为新证书生成一个新的密钥对 ---
    println!("   - 为新证书生成 P-256 密钥对...");
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec_key = EcKey::generate(&group)?;
    let new_pkey = PKey::from_ec_key(ec_key)?;

    // --- 3. 构建新证书 ---
    let mut builder = X509Builder::new()?;
    builder.set_version(2)?; // X.509 v3

    // 设置一个随机的序列号
    let serial_number = openssl::bn::BigNum::from_u32(rand::random())?;
    builder.set_serial_number(&serial_number.to_asn1_integer().unwrap())?;

    // 设置有效期为一年
    builder.set_not_before(&Asn1Time::days_from_now(0).unwrap())?;
    builder.set_not_after(&Asn1Time::days_from_now(365).unwrap())?;

    // 设置新证书的公钥
    builder.set_pubkey(&new_pkey)?;

    // 设置使用者名称 (Subject Name)
    let mut subject_name = X509NameBuilder::new()?;
    subject_name.append_entry_by_text("C", "CN")?;
    subject_name.append_entry_by_text("O", "My TLS Project")?;
    if let Some(cn) = args.get_one::<String>("common-name") {
        subject_name.append_entry_by_text("CN", cn)?;
    }
    builder.set_subject_name(&subject_name.build())?;

    // 设置签发者名称 (Issuer Name)，直接从 CA 证书获取
    builder.set_issuer_name(ca_cert.subject_name())?;

    // --- 4. 添加 X.509 V3 扩展 ---
    // 基本约束：指明这不是一个 CA 证书
    builder.append_extension(BasicConstraints::new().critical().build()?)?;
    
    // 密钥用途：数字签名 和 密钥加密
    builder.append_extension(
        KeyUsage::new()
            .critical()
            .digital_signature()
            .key_encipherment()
            .build()?
    )?;

    // 扩展密钥用途：根据命令行参数决定
    let is_server = args.get_flag("is-server");
    let is_client = args.get_flag("is-client");
    let mut ext_key_usage = ExtendedKeyUsage::new();
    if is_server { ext_key_usage.server_auth(); }
    if is_client { ext_key_usage.client_auth(); }
    if is_server || is_client {
        builder.append_extension(ext_key_usage.build()?)?;
    }

    // 使用者备用名称 (SAN)
    let context = builder.x509v3_context(Some(&ca_cert), None);
    let mut san = SubjectAlternativeName::new();
    let has_dns = if let Some(dns) = args.get_one::<String>("dns-names") {
        for name in dns.split(',') { san.dns(name.trim()); }
        true
    } else { false };
    let has_ips = if let Some(ips) = args.get_one::<String>("ip-addresses") {
        for ip in ips.split(',') { san.ip(ip.trim()); }
        true
    } else { false };
    
    if has_dns || has_ips {
        builder.append_extension(san.build(&context)?)?;
    }
    
    // --- 5. 使用 CA 私钥签名 ---
    // 检查 CA 私钥类型。EdDSA (如 Ed25519) 算法内置了哈希，不能显式指定
    let digest = if ca_pkey.id() == openssl::pkey::Id::ED25519 || ca_pkey.id() == openssl::pkey::Id::ED448 {
        MessageDigest::null()
    } else {
        MessageDigest::sha256()
    };
    builder.sign(&ca_pkey, digest)?;
    
    let new_cert = builder.build();

    // --- 6. 保存新证书和私钥 ---
    fs::write(out_cert, new_cert.to_pem()?)?;
    fs::write(out_key, new_pkey.private_key_to_pem_pkcs8()?)?;
    
    println!("由 CA '{}' 签发的新证书已生成:", ca_name);
    println!("   - 证书: {}", out_cert.display());
    println!("   - 私钥: {}", out_key.display());

    Ok(())
}