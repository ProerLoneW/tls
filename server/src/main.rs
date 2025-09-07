// server/src/main.rs
use clap::Parser;
use std::error::Error;
use std::fs::File;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tls_common::{display_server_tls_details, load_certs, load_private_key};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::rustls::{self, ServerConfig, RootCertStore};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use std::io::BufReader;
use rustls_pemfile;
use rustls::crypto::CryptoProvider;

#[derive(Parser)]
struct Args {
    #[clap(long, default_value = "127.0.0.1:8443")]
    addr: SocketAddr,
    #[clap(long, default_value = "server/server.crt")]
    cert: PathBuf,
    #[clap(long, default_value = "server/server.key")]
    key: PathBuf,
    #[clap(long, value_parser = ["1.2", "1.3"], default_value = "1.3")]
    tls_version: String,
    #[clap(long, default_value = "ca.crt", help = "用于验证客户端的 CA 根证书路径")]
    ca_cert: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // ✅ 第一步：创建 provider
    let provider = rustls::crypto::ring::default_provider();

    // ✅ 第二步：安装为全局默认
    CryptoProvider::install_default(provider)
        .expect("Failed to install default crypto provider");

    let args = Args::parse();
    run_server(
        args.addr,
        args.cert,
        args.key,
        &args.tls_version,
        args.ca_cert
    ).await
}

async fn run_server(
    addr: SocketAddr,
    cert_path: PathBuf,
    key_path: PathBuf,
    tls_version: &str,
    ca_cert_path: PathBuf,
) -> Result<(), Box<dyn Error>> {
    let certs = load_certs(&cert_path)?;
    let key = load_private_key(&key_path)?;

    let versions = if tls_version == "1.2" { 
        &[&rustls::version::TLS12] 
    } else { 
        &[&rustls::version::TLS13] 
    };

    // 创建一个根证书存储，并加载我们的 CA 证书
    let mut client_auth_roots = RootCertStore::empty();
    let mut pem = BufReader::new(File::open(ca_cert_path)?);
    for cert in rustls_pemfile::certs(&mut pem) {
        client_auth_roots.add(cert?)?;
    }

    // 创建一个要求客户端必须提供有效证书的验证器
    let client_verifier = WebPkiClientVerifier::builder(client_auth_roots.into()).build()?;

    // 无需证书认证情况
    // let config = ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
    //     .with_protocol_versions(versions)?
    //     .with_no_client_auth()
    //     .with_single_cert(certs, key.into())?;

    // 需要证书认证 题目要求
    let config = ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
        .with_protocol_versions(versions)?
        .with_client_cert_verifier(client_verifier) // <-- 从 with_no_client_auth() 改为这个
        .with_single_cert(certs, key.into())?;

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(addr).await?;
    println!("[Server] Listening on {} with TLS v{}", addr, tls_version);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let stream = acceptor.accept(stream).await.expect("accept error");
            if let Err(e) = handle_connection(stream).await {
                eprintln!("[Server] Error handling connection from {}: {}", peer_addr, e);
            }
        });
    }
}

async fn handle_connection(mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>) -> Result<(), Box<dyn Error>> {
    display_server_tls_details(&stream);
    let mut buf = vec![0; 1024];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 { break; }
        print!("[Server] Received: {}", String::from_utf8_lossy(&buf[..n]));
        stream.write_all(&buf[..n]).await?;
    }
    Ok(())
}