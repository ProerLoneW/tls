// server/src/main.rs
use clap::Parser;
use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tls_common::{display_server_tls_details, load_certs, load_private_key};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::rustls::{self, ServerConfig};
use tokio_rustls::TlsAcceptor;

#[derive(Parser)]
struct Args {
    #[clap(long, default_value = "127.0.0.1:8443")]
    addr: SocketAddr,
    #[clap(long, default_value = "cert.pem")]
    cert: PathBuf,
    #[clap(long, default_value = "key.pem")]
    key: PathBuf,
    #[clap(long, value_parser = ["1.2", "1.3"], default_value = "1.3")]
    tls_version: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    run_server(args.addr, args.cert, args.key, &args.tls_version).await
}

async fn run_server(addr: SocketAddr, cert_path: PathBuf, key_path: PathBuf, tls_version: &str) -> Result<(), Box<dyn Error>> {
    let certs = load_certs(&cert_path)?;
    let key = load_private_key(&key_path)?;

    let versions = if tls_version == "1.2" { &[&rustls::version::TLS12] } else { &[&rustls::version::TLS13] };

    // let config = ServerConfig::builder()
    //     .with_protocol_versions(versions)?
    //     .with_no_client_auth()
    //     .with_single_cert(certs, key.into())?;

    // 使用 builder_with_provider 开始，并遵循正确的调用顺序
    let config = ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
        .with_protocol_versions(versions)?
        .with_no_client_auth()
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