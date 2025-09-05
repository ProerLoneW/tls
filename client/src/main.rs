// client/src/main.rs

use clap::Parser;
use rustls::{pki_types::ServerName};
use std::error::Error;
use std::fs::File;
use std::io::{self, BufReader, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tls_common::display_client_tls_details;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::{self, ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

#[derive(Parser)]
struct Args {
    #[clap(long, default_value = "127.0.0.1:8443")]
    addr: SocketAddr,
    #[clap(long, default_value = "localhost")]
    hostname: String,
    #[clap(long, value_parser = ["1.2", "1.3"], default_value = "1.3")]
    tls_version: String,
    /// Path to the server's self-signed certificate to trust.
    #[clap(long, default_value = "cert.pem")]
    cafile: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    run_client(args.addr, &args.hostname, &args.tls_version, args.cafile).await
}

async fn run_client(
    addr: SocketAddr,
    hostname: &str,
    tls_version: &str,
    cafile: PathBuf,
) -> Result<(), Box<dyn Error>> {
    // 1. 创建一个新的、空的根证书存储
    let mut root_store = RootCertStore::empty();
    
    // 2. 打开我们自己的服务器证书文件 (cert.pem)
    let mut pem = BufReader::new(File::open(cafile)?);
    
    // 3. 读取证书并将其添加为我们唯一信任的根证书
    for cert in rustls_pemfile::certs(&mut pem) {
        root_store.add(cert?)?;
    }

    let versions = if tls_version == "1.2" {
        &[&rustls::version::TLS12]
    } else {
        &[&rustls::version::TLS13]
    };

    // 4. 使用这个只信任我们自己证书的 root_store 来创建配置
    //    我们不再需要 DangerousServerCertVerifier 了
    let config = ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
        .with_protocol_versions(versions)?
        .with_root_certificates(root_store)
        .with_no_client_auth();

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