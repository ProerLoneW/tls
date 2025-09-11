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
use tls_common::{CollectKeyLog, SniffState, SniffingStream}; // 新增
use tls_common::probe; // 新增

#[derive(Parser)]
struct Args {
    #[clap(long, default_value = "0.0.0.0:8899")]
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
    let mut config = ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
        .with_protocol_versions(versions)?
        .with_client_cert_verifier(client_verifier) // <-- 从 with_no_client_auth() 改为这个
        .with_single_cert(certs, key.into())?;

    // ★ 挂 KeyLog（Arc 要传入子任务里）
    let server_keylog = Arc::new(CollectKeyLog::default());
    config.key_log = server_keylog.clone();

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(addr).await?;
    println!("[Server] Listening on {} with TLS v{}", addr, tls_version);

    loop {
        let (tcp, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let server_keylog = server_keylog.clone();

        // tokio::spawn(async move {
        //     let stream = acceptor.accept(stream).await.expect("accept error");
        //     if let Err(e) = handle_connection(stream).await {
        //         eprintln!("[Server] Error handling connection from {}: {}", peer_addr, e);
        //     }
        // });

        tokio::spawn(async move {
            // ★ 包一层 tee，抓原始 TLS 字节
            let sniff = Arc::new(SniffState::default());
            let tee   = SniffingStream::new(tcp, sniff.clone());

            let mut tls = match acceptor.accept(tee).await {
                Ok(s) => s,
                Err(e) => { eprintln!("[Server] accept error from {}: {}", peer_addr, e); return; }
            };

            // 可选：打印 rustls 已暴露的协商信息
            // tls_common::display_server_tls_details(&tls);

            // ★ 抽取最终协商参数（解析 ServerHello + 解密后续握手）
            //    服务端视角：rx=客户端->服务端原始字节, tx=服务端->客户端原始字节
            let rx_bytes = sniff.snapshot_rx();
            let tx_bytes = sniff.snapshot_tx();

            match probe::extract_params(&rx_bytes, &tx_bytes, &server_keylog.lines()) {
                Ok(p) => {
                    println!("\n===== [Server Probe] TLS 1.3 negotiated parameters =====");
                    println!("Cipher Suite      : {}", p.cipher_suite);
                    println!("Named Group(curve): {}", p.named_group);
                    println!("Signature Alg     : {}", p.signature_algorithm.as_deref().unwrap_or("unknown"));
                    if let Some(ref der) = p.certificate_der {
                        println!("Server Certificate: {} bytes (DER)", der.len());
                    }
                    if let Some(ref oid) = p.ec_curve_oid {
                        println!("Cert EC Curve OID : {}", oid);
                    }
                    if let Some(ref pk) = p.ec_pubkey_uncompressed_hex {
                        println!("EC Public Key(04|X|Y): {}", &pk[..pk.len().min(120)]);
                    }
                    println!("=========================================================\n");
                }
                Err(e) => eprintln!("[Server Probe] extract failed: {:#}", e),
            }

            // 进入 echo 循环
            let mut buf = vec![0u8; 1024];
            loop {
                let n = match tls.read(&mut buf).await { Ok(0)=>break, Ok(n)=>n, Err(e)=>{eprintln!("[Server] read error: {}", e); break;} };
                print!("[Server] Received: {}", String::from_utf8_lossy(&buf[..n]));
                if let Err(e) = tls.write_all(&buf[..n]).await { eprintln!("[Server] write error: {}", e); break; }
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