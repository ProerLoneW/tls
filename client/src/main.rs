// client/src/main.rs

use clap::Parser;
use rustls::{pki_types::ServerName};
use std::error::Error;
use std::fs::File;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tls_common::{display_client_tls_details, load_certs, load_private_key};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
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
    run_client_recv(
        args.addr,
        &args.hostname,
        &args.tls_version,
        args.cafile,
        args.cert,
        args.key,
    )
    .await
}

async fn run_client_recv(
    addr: SocketAddr,
    hostname: &str,
    tls_version: &str,
    cafile: PathBuf,
    cert_path: PathBuf,
    key_path: PathBuf,
) -> Result<(), Box<dyn Error>> {
    // 根证书存储
    let mut root_store = RootCertStore::empty();
    let mut pem = std::io::BufReader::new(File::open(cafile)?);
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

    // 拆分读/写两半
    let (rd, mut wr) = tokio::io::split(stream);

    // 任务1：从 stdin 读一行就发到服务端
    let t_send = tokio::spawn(async move {
        let mut in_lines = TokioBufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(mut line)) = in_lines.next_line().await {
            if !line.ends_with('\n') { line.push('\n'); } // 以 '\n' 作为消息分隔
            if wr.write_all(line.as_bytes()).await.is_err() { break; }
        }
    });

    // 任务2：持续读取服务器的每一行回包并打印
    let t_recv = tokio::spawn(async move {
        let mut sock_lines = TokioBufReader::new(rd).lines();
        while let Ok(Some(line)) = sock_lines.next_line().await {
            println!("[Client] Received: {line}");
        }
    });

    let _ = tokio::join!(t_send, t_recv);

    Ok(())
}