use clap::Parser;
use std::{collections::HashMap, error::Error, fs::File, net::SocketAddr, path::PathBuf, sync::{Arc, atomic::{AtomicU64, Ordering}}};
use rustls_pemfile;
use tokio::{net::TcpListener, io::{AsyncWriteExt, AsyncBufReadExt, BufReader}, sync::{RwLock, Mutex as AsyncMutex, broadcast}, task::JoinHandle, time::{interval, Duration}};
use tokio_rustls::{rustls::{self, ServerConfig, RootCertStore}, TlsAcceptor};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use rustls::crypto::CryptoProvider;

use serde::{Serialize, Deserialize};

use tls_common::{load_certs, load_private_key, CollectKeyLog, SniffState, SniffingStream};
use tls_common::probe; // 里边已经提供 extract_params()
use serde_json::json;

// ------------------------- CLI -------------------------
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

// ------------------------- 公用时间 -------------------------
fn now_millis() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()
}

// ------------------------- 可视化状态 -------------------------
#[derive(Clone, Serialize)]
struct ConnSummary {
    id: u64,
    peer_addr: String,
    start_ts: u128,
    cipher_suite: Option<String>,
    named_group: Option<String>,
}

#[derive(Clone, Serialize)]
struct ConnDetail {
    id: u64,
    peer_addr: String,
    start_ts: u128,
    // 协商参数
    cipher_suite: Option<String>,
    named_group: Option<String>,
    signature_algorithm: Option<String>,
    certificate_der_len: Option<usize>,
    ec_curve_oid: Option<String>,
    ec_pubkey_uncompressed_hex_short: Option<String>,
    // 消息日志（客户端->服务端）
    messages: Vec<Msg>,
}

#[derive(Clone, Serialize)]
struct Msg {
    ts_ms: u128,
    text: String,
}

struct ConnInfo {
    summary: ConnSummary,
    detail: ConnDetail,
}

#[derive(Clone)]
struct AppState {
    conns: Arc<RwLock<HashMap<u64, ConnInfo>>>,
    next_id: Arc<AtomicU64>,
    evt_tx: broadcast::Sender<String>,     // 发送给 SSE 的 JSON 事件
    ui_handle: Arc<AsyncMutex<Option<JoinHandle<()>>>>,
    lis_handle: Arc<AsyncMutex<Option<JoinHandle<()>>>>,
    acceptor: TlsAcceptor,
    keylog: Arc<CollectKeyLog>,
}

impl AppState {
    fn new(acceptor: TlsAcceptor, keylog: Arc<CollectKeyLog>) -> (Self, broadcast::Receiver<String>) {
        let (tx, rx) = broadcast::channel(256);
        (Self {
            conns: Arc::new(RwLock::new(HashMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
            evt_tx: tx,
            ui_handle: Arc::new(AsyncMutex::new(None)),
            lis_handle: Arc::new(AsyncMutex::new(None)),
            acceptor,
            keylog,
        }, rx)
    }
}

// ------------------------- Web UI (axum) -------------------------
mod web {
    use super::*;
    use axum::{
        extract::{Path, State},
        response::{Html, Sse, sse::Event},
        routing::{get, post},
        Json, Router,
    };
    use tokio_stream::{wrappers::BroadcastStream, StreamExt};

    #[derive(Deserialize)]
    pub struct ListenReq { addr: String }

    pub async fn sse(State(state): State<AppState>) -> Sse<impl futures_core::Stream<Item=Result<Event, std::convert::Infallible>>> {
        let rx = state.evt_tx.subscribe();
        let stream = BroadcastStream::new(rx).filter_map(|msg| {
            match msg {
                Ok(json) => Some(Ok(Event::default().data(json))),
                Err(_) => None,
            }
        });
        Sse::new(stream)
    }

    pub async fn index() -> Html<String> {
        Html(INDEX_HTML.to_string())
    }

    pub async fn list(State(state): State<AppState>) -> Json<Vec<ConnSummary>> {
        let map = state.conns.read().await;
        Json(map.values().map(|c| c.summary.clone()).collect())
    }

    pub async fn detail(State(state): State<AppState>, Path(id): Path<u64>) -> Json<Option<ConnDetail>> {
        let map = state.conns.read().await;
        Json(map.get(&id).map(|c| c.detail.clone()))
    }

    pub async fn listen(State(state): State<AppState>, Json(req): Json<ListenReq>) -> Json<serde_json::Value> {
        // 停掉旧 listener
        if let Some(handle) = state.lis_handle.lock().await.take() {
            handle.abort();
        }
        // 启动新 listener
        let addr: SocketAddr = req.addr.parse().map_err(|_| ()).unwrap();
        let new_handle = super::spawn_tls_listener(addr, state.clone());
        *state.lis_handle.lock().await = Some(new_handle);
        Json(serde_json::json!({"ok": true, "listening": req.addr}))
    }

    // 新增：停止监听
    pub async fn stop(State(state): State<AppState>) -> Json<serde_json::Value> {
        if let Some(handle) = state.lis_handle.lock().await.take() {
            handle.abort(); // 终止当前 listener 任务
        }
        Json(json!({"ok": true, "listening": false}))
    }

    pub async fn serve(state: AppState) -> JoinHandle<()> {
        let app = Router::new()
            .route("/", get(index))
            .route("/events", get(sse))
            .route("/api/connections", get(list))
            .route("/api/connections/:id", get(detail))
            .route("/api/listen", post(listen))
            .route("/api/stop", post(stop))
            .with_state(state.clone());

        let addr = SocketAddr::from(([127,0,0,1], 3000));
        println!("[WebUI] open http://{addr}/");

        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
            axum::serve(listener, app.into_make_service()).await.unwrap();
        })
    }

    // 极简单页：左列表 + 右详情；SSE 实时刷新
    pub const INDEX_HTML: &str = r#"
<!doctype html><meta charset="utf-8">
<title>TLS Monitor</title>

<style>
body {
    font-family:ui-sans-serif,system-ui,Arial;
    margin:0;
    display:flex;
    height:100vh
}
#left{width:40%;border-right:1px solid #ddd;display:flex;flex-direction:column}
#right{flex:1;padding:12px;overflow:auto}
header {
    display:flex;               /* 横向排列 */
    align-items:center;
    gap:8px;                    /* 控件间距 */
    padding:10px;
    border-bottom:1px solid #ddd;
    flex-wrap:nowrap;           /* ❗ 不允许换行 */
}
table{width:100%;border-collapse:collapse}
th,td{padding:6px;border-bottom:1px solid #eee;font-size:14px}
tr:hover{background:#f7f7f7;cursor:pointer}
pre{white-space:pre-wrap;word-break:break-all;background:#fafafa;border:1px solid #eee;padding:8px}
label{font-size:14px;margin-right:6px}
input{padding:6px;font-size:14px}
button{padding:6px 10px;margin-left:6px}
.badge{padding:2px 6px;border:1px solid #ccc;border-radius:4px;background:#f5f5f5;margin-left:6px}
#right{position:relative; padding:12px; overflow:auto}
#detailPanel{display:none}               /* 默认隐藏 */
#detailPanel.open{display:block}         /* 添加 .open 类即显示 */
#placeholder{ color:#999; padding:12px; display:block; }  /* 初始可见 */
#detailHeader{
  display:flex; align-items:center; justify-content:space-between;
  position:sticky; top:0; background:#fff;
  padding:0 0 8px 0; margin:0 0 8px 0; border-bottom:1px solid #eee;
}
#closeBtn{
  border:none; background:transparent; cursor:pointer;
  font-size:20px; line-height:1; padding:2px 6px;
}
#placeholder{ color:#999; padding:12px; }
</style>

<div id="left">
    <header>
        <label>Listen:</label>
        <input id="addr" value="0.0.0.0:8899" />
        <button onclick="start()">Start</button>
        <button onclick="stop()">Stop</button>
        <span id="status" class="badge">stopped</span>
    </header>
    <div style="padding:10px;overflow:auto">
        <table id="tbl">
        <thead><tr><th>ID</th><th>Peer</th><th>Suite</th><th>Group</th><th>Since</th></tr></thead>
        <tbody id="rows"></tbody>
        </table>
    </div>
</div>
<div id="right">
    <!-- 可折叠详情面板 -->
    <div id="detailPanel">
        <div id="detailHeader">
            <h3 style="margin:0">Details</h3>
            <button id="closeBtn" onclick="closeDetails()" title="Close">×</button>
        </div>
        <div id="detail"></div>
        <h3>Messages (client → server)</h3>
        <div id="msgs"></div>
    </div>

    <!-- 关闭时显示的占位提示 -->
    <div id="placeholder">Click a connection to view details</div>
</div>
<script>
let cur = null;
async function start(){
    const addr = document.getElementById('addr').value.trim();
    const r = await fetch('/api/listen',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({addr})});
    const j = await r.json();
    document.getElementById('status').innerText = j.ok ? ('listening '+addr) : 'error';
}
async function stop(){
    const r = await fetch('/api/stop', { method:'POST' });
    const j = await r.json();
    document.getElementById('status').innerText = j.ok ? 'stopped' : 'error';
  await reloadList(); // 清理列表（因为不会再有新连接了）
}
function human(ts){const d=new Date(Number(ts));return d.toLocaleTimeString();}
async function reloadList(){
    const r = await fetch('/api/connections'); const a = await r.json();
    const rows = document.getElementById('rows'); rows.innerHTML='';
    a.forEach(x=>{
    const tr = document.createElement('tr');
    tr.onclick = ()=>show(x.id);
    tr.innerHTML = `<td>${x.id}</td><td>${x.peer_addr}</td><td>${x.cipher_suite||''}</td><td>${x.named_group||''}</td><td>${human(x.start_ts)}</td>`;
    rows.appendChild(tr);
});
}
function openDetails(){
  document.getElementById('detailPanel').classList.add('open');
  document.getElementById('placeholder').style.display = 'none';
}
function closeDetails(){
  cur = null;
  document.getElementById('detailPanel').classList.remove('open');
  document.getElementById('detail').innerHTML = '';
  document.getElementById('msgs').innerHTML = '';
  document.getElementById('placeholder').style.display = 'block';
}
async function show(id){
    cur = id;
    const r = await fetch('/api/connections/'+id); const d = await r.json();
    if(!d){document.getElementById('detail').innerHTML='(not found)';return;}
    // 打开面板
    openDetails();
    document.getElementById('detail').innerHTML =
    `<pre>${JSON.stringify({
        id:d.id,peer:d.peer_addr,start:d.start_ts,cipher_suite:d.cipher_suite,
        named_group:d.named_group,signature_algorithm:d.signature_algorithm,
        certificate_der_len:d.certificate_der_len,ec_curve_oid:d.ec_curve_oid,
        ec_pubkey_uncompressed_hex_short:d.ec_pubkey_uncompressed_hex_short
    },null,2)}</pre>`;
    const box=document.getElementById('msgs'); box.innerHTML='';
    (d.messages||[]).forEach(m=>appendMsg(id,m));
}
function appendMsg(id,m){
    if(cur!==id) return;
    const box = document.getElementById('msgs');
    const div=document.createElement('div');
    div.innerHTML = `<div><span class="badge">${human(m.ts_ms)}</span> ${m.text}</div>`;
    box.appendChild(div); box.scrollTop=box.scrollHeight;
}
reloadList();
const es = new EventSource('/events');
es.onmessage = ev=>{
    const e = JSON.parse(ev.data);
    if(e.type==='conn_new'||e.type==='conn_closed'){ reloadList(); }
    if(e.type==='msg'){ appendMsg(e.id,e.msg); }
}
</script>
"#;
}

// ------------------------- TLS 监听（可热切换端口） -------------------------
fn spawn_tls_listener(addr: SocketAddr, state: AppState) -> JoinHandle<()> {
    println!("[TLS] Listening on {}", addr);
    tokio::spawn(async move {
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => { eprintln!("[TLS] bind {} failed: {}", addr, e); return; }
        };

        loop {
            let (tcp, peer_addr) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => { eprintln!("[TLS] accept err: {}", e); continue; }
            };

            let acceptor = state.acceptor.clone();
            let keylog = state.keylog.clone();
            let conns = state.conns.clone();
            let tx = state.evt_tx.clone();
            let next_id = state.next_id.clone();

            tokio::spawn(async move {
                // tee 抓包
                let sniff = Arc::new(SniffState::default());
                let tee   = SniffingStream::new(tcp, sniff.clone());

                let tls = match acceptor.accept(tee).await {
                    Ok(s) => s,
                    Err(e) => { eprintln!("[TLS] accept error from {}: {}", peer_addr, e); return; }
                };

                // 分配连接 ID、登记
                let id = next_id.fetch_add(1, Ordering::SeqCst);
                let start_ts = now_millis();

                // 解析协商参数
                let rx_bytes = sniff.snapshot_rx();
                let tx_bytes = sniff.snapshot_tx();
                let mut cipher_suite = None;
                let mut named_group = None;
                let mut signature_algorithm = None;
                let mut certificate_der_len = None;
                let mut ec_curve_oid = None;
                let mut ec_pubkey_uncompressed_hex_short = None;

                if let Ok(p) = probe::extract_params(&rx_bytes, &tx_bytes, &keylog.lines()) {
                    cipher_suite = Some(p.cipher_suite);
                    named_group = Some(p.named_group);
                    signature_algorithm = p.signature_algorithm;
                    certificate_der_len = p.certificate_der.map(|d| d.len());
                    ec_curve_oid = p.ec_curve_oid;
                    ec_pubkey_uncompressed_hex_short = p.ec_pubkey_uncompressed_hex
                        .map(|s| if s.len()>120 { format!("{}...", &s[..120]) } else { s });
                }

                // 写入状态表
                {
                    let mut map = conns.write().await;
                    map.insert(id, ConnInfo {
                        summary: ConnSummary {
                            id, peer_addr: peer_addr.to_string(), start_ts,
                            cipher_suite: cipher_suite.clone(),
                            named_group: named_group.clone(),
                        },
                        detail: ConnDetail {
                            id, peer_addr: peer_addr.to_string(), start_ts,
                            cipher_suite: cipher_suite.clone(),
                            named_group: named_group.clone(),
                            signature_algorithm: signature_algorithm.clone(),
                            certificate_der_len,
                            ec_curve_oid: ec_curve_oid.clone(),
                            ec_pubkey_uncompressed_hex_short: ec_pubkey_uncompressed_hex_short.clone(),
                            messages: Vec::new(),
                        },
                    });
                }
                let _ = tx.send(serde_json::json!({"type":"conn_new","id":id}).to_string());

                // 全双工：这里只需要读客户端→服务端，并记录/推送
                let (rd, _wr) = tokio::io::split(tls);
                let mut lines = BufReader::new(rd).lines();

                loop {
                    match lines.next_line().await {
                        Ok(Some(line)) => {
                            // 记录到状态 + 推给 SSE
                            let m = Msg { ts_ms: now_millis(), text: line.clone() };
                            {
                                let mut map = conns.write().await;
                                if let Some(info) = map.get_mut(&id) {
                                    info.detail.messages.push(m.clone());
                                }
                            }
                            let _ = tx.send(serde_json::json!({"type":"msg","id":id,"msg":m}).to_string());
                        }
                        Ok(None) => break, // 客户端关闭
                        Err(e) => { eprintln!("[TLS] read error {}: {}", peer_addr, e); break; }
                    }
                }

                // 连接结束 → 清理并通知
                {
                    let mut map = conns.write().await;
                    map.remove(&id);
                }
                let _ = tx.send(serde_json::json!({"type":"conn_closed","id":id,"ts_ms":now_millis()}).to_string());
            });
        }
    })
}

// ------------------------- 入口：初始化 TLS、WebUI、监听器 -------------------------
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 安装 ring provider
    CryptoProvider::install_default(rustls::crypto::ring::default_provider())
        .expect("install default crypto provider");

    let args = Args::parse();

    // 构造 ServerConfig（mTLS）
    let certs = load_certs(&args.cert)?;
    let key = load_private_key(&args.key)?;

    let versions = if args.tls_version == "1.2" { &[&rustls::version::TLS12] } else { &[&rustls::version::TLS13] };

    let mut client_auth_roots = RootCertStore::empty();
    let mut pem = std::io::BufReader::new(File::open(&args.ca_cert)?);
    for cert in rustls_pemfile::certs(&mut pem) { client_auth_roots.add(cert?)?; }
    let client_verifier = WebPkiClientVerifier::builder(client_auth_roots.into()).build()?;

    let mut cfg = ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
        .with_protocol_versions(versions)?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, key.into())?;

    // KeyLog
    let keylog = Arc::new(CollectKeyLog::default());
    cfg.key_log = keylog.clone();

    let acceptor = TlsAcceptor::from(Arc::new(cfg));

    // 全局状态 & Web UI
    let (state, _rx) = AppState::new(acceptor.clone(), keylog.clone());
    let ui_handle = web::serve(state.clone()).await;
    *state.ui_handle.lock().await = Some(ui_handle);

    // 启动初始 TLS 监听（默认 CLI 参数）
    // let lis_handle = spawn_tls_listener(args.addr, state.clone());
    // *state.lis_handle.lock().await = Some(lis_handle);

    // 主任务什么也不做，交给子任务跑；Ctrl+C 退出
    println!("[Server] UI at http://127.0.0.1:3000  |  TLS listening on {}", args.addr);
    loop { tokio::signal::ctrl_c().await?; break; }
    Ok(())
}
