// tls_common/src/lib.rs
use rustls::{pki_types::{CertificateDer, PrivateKeyDer}};
use std::fs;
use std::path::Path;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use x509_parser::prelude::*;

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
            // --- 新增解析逻辑 ---
            match parse_x509_certificate(cert_der.as_ref()) {
                Ok((_, parsed_cert)) => {
                    println!("Client Certificate Subject: {}", parsed_cert.subject());
                }
                Err(_) => {
                    println!("Could not parse client certificate.");
                }
            }
            // --- 结束新增 ---
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
            // --- 新增解析逻辑 ---
            match parse_x509_certificate(cert_der.as_ref()) {
                Ok((_, parsed_cert)) => {
                    println!("Client Certificate Subject: {}", parsed_cert.subject());
                }
                Err(_) => {
                    println!("Could not parse client certificate.");
                }
            }
            // --- 结束新增 ---
        }
    }
    println!("--------------------------------------\n");
}