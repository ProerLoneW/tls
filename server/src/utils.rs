async fn run_server_recv(
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
    let mut pem = std::io::BufReader::new(File::open(ca_cert_path)?);
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

            // --- 全双工：拆读/写，并行进行 ---
            let peer_addr_str = peer_addr.to_string();
            let (rd, wr) = tokio::io::split(tls);
            let wr = Arc::new(AsyncMutex::new(wr));

            // 任务1：读取客户端每一行 → 按 JSONL 记录 →（示例）回显
            let wr_for_reader = wr.clone();
            let peer_for_reader = peer_addr_str.clone();
            let t_read_and_echo = tokio::spawn(async move {
                let r = BufReader::new(rd);        // ✅ tokio::io::BufReader
                let mut lines = r.lines();         // ✅ 只创建一次 Lines
                loop {
                    match lines.next_line().await {
                        Ok(Some(line)) => {
                            // 记录：对方（client）发来的消息
                            log_incoming("server", "client", &peer_for_reader, &line);

                            // （可选）回显：证明写通道可用；也可改成你自己的服务端业务逻辑
                            let mut w = wr_for_reader.lock().await;
                            if w.write_all(line.as_bytes()).await.is_err() { break; }
                            if w.write_all(b"\n").await.is_err() { break; }
                            if w.flush().await.is_err() { break; }
                        }
                        Ok(None) => break,                   // 客户端正常关闭
                        Err(e) => { eprintln!("[Server] read error: {e}"); break; }
                    }
                }
            });

            // 任务2（可选）：服务器“主动推送”心跳，演示 full-duplex
            // let wr_for_push = wr.clone();
            // let t_push = tokio::spawn(async move {
            //     let mut tick = interval(Duration::from_secs(10));
            //     loop {
            //         tick.tick().await;
            //         let msg = format!("[server-heartbeat] {}\n", now_millis());
            //         let mut w = wr_for_push.lock().await;
            //         if w.write_all(msg.as_bytes()).await.is_err() { break; }
            //         if w.flush().await.is_err() { break; }
            //     }
            // });
            
            // 任一任务结束就收尾
            let _ = tokio::join!(t_read_and_echo);
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