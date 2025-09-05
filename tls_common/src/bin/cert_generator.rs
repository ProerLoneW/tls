// tls_common/src/bin/cert_generator.rs

use clap::Parser;
use rcgen::{CertificateParams, DistinguishedName, KeyPair}; // <-- 引入 KeyPair
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    #[clap(long, default_value = "cert.pem")]
    cert_path: PathBuf,
    #[clap(long, default_value = "key.pem")]
    key_path: PathBuf,
    #[clap(long, default_value = "localhost")]
    hostname: String,
}

fn main() {
    let args = Args::parse();

    if args.cert_path.exists() && args.key_path.exists() {
        println!("Certificates already exist. Skipping generation.");
        return;
    }

    // --- 以下是修改的核心部分 ---

    // 1. 创建证书参数
    let alt_names = vec![args.hostname];
    let mut params = CertificateParams::new(alt_names).unwrap();
    params.distinguished_name = DistinguishedName::new();

    // 2. 生成一个新的密钥对
    let key_pair = KeyPair::generate().unwrap();

    // 3. 使用参数和密钥对创建自签名证书
    //    注意：这里调用的是 params.self_signed() 而不是 Certificate::from_params()
    let cert = params.self_signed(&key_pair).unwrap();

    // 4. 将证书和私钥分别序列化并写入文件
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem(); // 从 key_pair 获取私钥

    fs::write(&args.cert_path, cert_pem).unwrap();
    fs::write(&args.key_path, key_pem).unwrap();

    // --- 修改结束 ---

    println!("Generated new certificate and private key.");
    println!("  - Certificate: {}", args.cert_path.display());
    println!("  - Private Key: {}", args.key_path.display());
}