// tls_common/src/lib.rs
use rustls::{pki_types::{CertificateDer, PrivateKeyDer}};
use std::{fs};
use std::path::Path;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

pub mod keylog;
pub mod sniff;
pub mod probe;

pub use keylog::CollectKeyLog;
pub use sniff::{SniffState, SniffingStream};


// 从文件加载证书
pub fn load_certs(path: &Path) -> std::io::Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut std::io::BufReader::new(fs::File::open(path)?))
        .collect()
}

// 从文件加载私钥
pub fn load_private_key(path: &Path) -> std::io::Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut std::io::BufReader::new(fs::File::open(path)?))
        .map(|result| result.unwrap())
}

// 为服务器端打印TLS连接参数
pub fn display_server_tls_details(stream: &ServerTlsStream<TcpStream>) {
    let (_, session) = stream.get_ref();
    println!("\n--- [Server] TLS Connection Details ---");
    if let Some(version) = session.protocol_version() {
        println!("Protocol Version: {:?}", version);
    }
    if let Some(suite) = session.negotiated_cipher_suite() {
        println!("Cipher Suite: {:?}", suite.suite());
    }
    if let Some(certs) = session.peer_certificates() {
        if let Some(cert_der) = certs.first() {
            // --- 打印客户端证书 ---
            print_certificate_details(cert_der);
        }
    }
    println!("--------------------------------------\n");
}

// 为客户端打印TLS连接参数
pub fn display_client_tls_details(stream: &ClientTlsStream<TcpStream>) {
    let (_, session) = stream.get_ref();
    println!("\n--- [Client] TLS Connection Details ---");
    if let Some(version) = session.protocol_version() {
        println!("Protocol Version: {:?}", version);
    }
    if let Some(suite) = session.negotiated_cipher_suite() {
        println!("Cipher Suite: {:?}", suite.suite());
    }
    if let Some(certs) = session.peer_certificates() {
        if let Some(cert_der) = certs.first() {
            // --- 打印服务器证书 ---
            print_certificate_details(cert_der);
        }
    }
    println!("--------------------------------------\n");
}

use x509_parser::der_parser::oid::Oid;
use x509_parser::der_parser::asn1_rs::{Any, Tag};

// fn get_ec_curve_oid<'a>(parameters: Option<&'a Any>) -> Option<Oid<'a>> {
//     let any = parameters?;
//     println!("Debug: EC parameters ASN.1 data: {:?}", any);
//     println!("Debug: EC parameters ASN.1 tag: {:?}", any.tag());
//     if any.tag() == Tag::Oid {
//         match Oid::from_der(any.data) {
//             Ok((_, oid)) => {
//                 println!("EC Curve OID: {}", oid);
//                 Some(oid)
//             } // ✅ 正确：返回 owned 值
//             Err(e) => {
//                 println!("Failed to parse EC curve OID: {:?}", e);
//                 None
//             }
//         }
//     } else {
//         println!("EC parameters is not an OID.");
//         None
//     }
// }

fn get_ec_curve_oid<'a>(parameters: Option<&'a Any>) -> Result<Option<Oid<'a>>, &'static str> {
    let any = match parameters {
        Some(p) => p,
        None => return Ok(None),
    };

    // 检查是否是 OID tag (Tag 6)
    if any.tag() != Tag::Oid {
        return Err("EC parameters is not an OID");
    }

    // 直接从 data 创建 OID
    match Oid::try_from(any) {
        Ok(oid) => Ok(Some(oid)),
        Err(_) => Err("Failed to parse OID from bytes"),
    }
}

/// 一个通用的函数，用于解析并打印证书的详细信息
fn print_certificate_details(cert_der: &CertificateDer) {
    match parse_x509_certificate(cert_der.as_ref()) {
        Ok((_, cert)) => {
            println!("  - Version: {}", cert.version());
            println!("  - Serial Number: {}", hex::encode(cert.raw_serial()));
            println!("  - Subject: {}", cert.subject());
            println!("  - Issuer: {}", cert.issuer());
            println!("  - Validity: Not Before: {}, Not After: {}", cert.validity().not_before, cert.validity().not_after);
            
            let signature_algorithm = match cert.signature.algorithm.to_string().as_str() {
                "1.2.840.113549.1.1.11" => "  - Signature Algorithm: sha256WithRSAEncryption",
                "1.2.840.113549.1.1.12" => "  - Signature Algorithm: sha384WithRSAEncryption",
                "1.2.840.113549.1.1.13" => "  - Signature Algorithm: sha512WithRSAEncryption",
                "1.2.840.10045.4.3.1" => "  - Signature Algorithm: ecdsa-with-SHA224",
                "1.2.840.10045.4.3.2" => "  - Signature Algorithm: ecdsa-with-SHA256",
                "1.2.840.10045.4.3.3" => "  - Signature Algorithm: ecdsa-with-SHA384",
                "1.2.840.10045.4.3.4" => "  - Signature Algorithm: ecdsa-with-SHA512",
                _ => "Unknown",
            };
            println!("  - Signature Algorithm: {}", signature_algorithm);

            let pkey = cert.public_key();
            println!("\n  --- Public Key Info ---");
            println!("    - Public Key Algorithm: {}", 
                match pkey.algorithm.oid().to_string().as_str() {
                    "1.2.840.10045.2.1" => "EC", // ecPublicKey
                    "1.2.840.113549.1.1.1" => "RSA", // rsaEncryption
                    "1.2.840.10040.4.1" => "DSA", // 
                    _ => "Unknown",
                }
            );

            // 解析公钥内容
            if let Ok(public_key) = pkey.parsed() {
                match public_key {
                    // EC 公钥
                    PublicKey::EC(ec_pubkey) => {
                        println!("    - Type: Elliptic Curve");
                        match get_ec_curve_oid(pkey.algorithm.parameters.as_ref()) {
                            Ok(Some(curve_oid)) => {
                                println!("    - Curve OID: {}", curve_oid);
                                let curve_name = match curve_oid.to_string().as_str() {
                                    "1.2.840.10045.3.1.7" => "P-256 (secp256r1)",
                                    "1.3.132.0.34" => "P-384",
                                    "1.3.132.0.35" => "P-521",
                                    _ => "Unknown",
                                };
                                println!("    - Curve Name: {}", curve_name);
                            }
                            Ok(None) => {
                                println!("  - Curve: Not specified (e.g., implicit)");
                            }
                            Err(e) => {
                                println!("  - Failed to parse EC curve OID: {}", e);
                            }
                        }

                        let hex_str = hex::encode(ec_pubkey.data());
                        let hex_preview = &hex_str[..hex_str.len().min(64)]; // 64 hex chars = 32 bytes
                        println!("    - Public Key (Hex): {}...", hex_preview);
                    }

                    // RSA 公钥
                    PublicKey::RSA(rsa_pubkey) => {
                        println!("    - Type: RSA");
                        let modulus_hex = hex::encode(rsa_pubkey.modulus);
                        let mod_preview = &modulus_hex[..modulus_hex.len().min(64)];
                        println!("    - Modulus (Hex): {}...", mod_preview);
                        let exponent_hex = hex::encode(rsa_pubkey.exponent);
                        let exp_preview = &exponent_hex[..exponent_hex.len().min(16)];
                        println!("    - Exponent (Hex): {}...", exp_preview);
                    }

                    // DSA TODO
                    PublicKey::DSA(y) => {
                        println!("    - Type: DSA");
                        let y_hex = hex::encode(y);
                        let y_preview = &y_hex[..y_hex.len().min(64)];
                        println!("    - Public Key (Y) (Hex): {}...", y_preview);
                    }

                    _ => {
                        println!("    - Type: Other/Unknown");
                    }
                }
            } else {
                println!("    - Public Key: Failed to parse");
            }

            println!("\n  --- Extensions ---");
            for ext in cert.extensions() {
                println!("    - OID: {}, Critical: {}", ext.oid, ext.critical);
                match ext.parsed_extension() {
                    ParsedExtension::SubjectAlternativeName(san) => {
                        println!("      - Subject Alternative Name (SAN):");
                        for name in &san.general_names {
                            println!("        - {:?}", name);
                        }
                    }
                    ParsedExtension::BasicConstraints(bc) => {
                        println!("      - Basic Constraints: Is CA: {}", bc.ca);
                    }
                    // 可以按需添加更多扩展的解析和打印
                    _ => println!("      - (Extension not parsed in detail)"),
                }
            }
        }
        Err(e) => {
            println!("Could not parse certificate: {}", e);
        }
    }
}