// client/src/main.rs

use clap::Parser;
use rustls::{pki_types::ServerName};
use std::error::Error;
use std::fs::File;
use std::io::{self, BufReader, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tls_common::{display_client_tls_details, load_certs, load_private_key};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::{self, ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use rustls_pemfile;

#[derive(Parser)]
struct Args {
    #[clap(long, default_value = "127.0.0.1:8899")]
    // #[clap(long, default_value = "172.20.10.6:8899")]
    addr: SocketAddr,
    #[clap(long, default_value = "localhost")]
    hostname: String,
    #[clap(long, value_parser = ["1.2", "1.3"], default_value = "1.3")]
    tls_version: String,
    #[clap(long, default_value = "ca.crt", help = "用于验证服务器的 CA 根证书路径")]
    cafile: PathBuf,
    #[clap(long, default_value = "client/client.crt", help = "客户端证书路径")]
    cert: PathBuf,
    #[clap(long, default_value = "client/client.key", help = "客户端私钥路径")]
    key: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    run_client(
        args.addr,
        &args.hostname,
        &args.tls_version,
        args.cafile,
        args.cert,
        args.key,
    )
    .await
}

async fn run_client(
    addr: SocketAddr,
    hostname: &str,
    tls_version: &str,
    cafile: PathBuf,
    cert_path: PathBuf,
    key_path: PathBuf,
) -> Result<(), Box<dyn Error>> {
    // 根证书存储
    let mut root_store = RootCertStore::empty();
    let mut pem = BufReader::new(File::open(cafile)?);
    for cert in rustls_pemfile::certs(&mut pem) {
        root_store.add(cert?)?;
    }

    let versions = if tls_version == "1.2" {
        &[&rustls::version::TLS12]
    } else {
        &[&rustls::version::TLS13]
    };

    // 加载客户端自己的证书和私钥
    let client_certs = load_certs(&cert_path)?;
    let client_key = load_private_key(&key_path)?;

    // 不发送客户端证书
    // let config = ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
    //     .with_protocol_versions(versions)?
    //     .with_root_certificates(root_store)
    //     .with_no_client_auth();

    // 发送客户端证书 使用客户端证书和私钥构建 ClientConfig
    let config = ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
        .with_protocol_versions(versions)?
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key.into())?;

    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(addr).await?;
    let domain = ServerName::try_from(hostname)?.to_owned();
    
    println!("[Client] Attempting to connect to {}...", addr);
    
    // 现在这个 await 应该可以成功完成了
    let mut stream = connector.connect(domain, stream).await?;

    println!("[Client] TLS connection established with {}", addr);
    display_client_tls_details(&stream);

    loop {
        print!("[Client] Enter message (or Ctrl+D to exit): ");
        io::stdout().flush()?;
        let mut line = String::new();
        if io::stdin().read_line(&mut line)? == 0 {
            println!("\n[Client] Disconnecting.");
            break;
        }
        stream.write_all(line.as_bytes()).await?;
        let mut res = vec![0; 1024];
        let n = stream.read(&mut res).await?;
        if n == 0 {
            println!("\n[Server] Closed connection.");
            break;
        }
        print!("[Client] Received: {}", String::from_utf8_lossy(&res[..n]));
    }
    Ok(())
}