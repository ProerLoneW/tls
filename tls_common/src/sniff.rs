use std::{pin::Pin, sync::{Arc, Mutex}, task::{Context, Poll}};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default)]
pub struct SniffState {
    rx: Mutex<Vec<u8>>, // 对“当前端”来说：读到的（对端->本端）
    tx: Mutex<Vec<u8>>, // 写出去的（本端->对端）
}
impl SniffState {
    pub fn snapshot_rx(&self) -> Vec<u8> { self.rx.lock().unwrap().clone() }
    pub fn snapshot_tx(&self) -> Vec<u8> { self.tx.lock().unwrap().clone() }
    fn push_rx(&self, data: &[u8]) { self.rx.lock().unwrap().extend_from_slice(data); }
    fn push_tx(&self, data: &[u8]) { self.tx.lock().unwrap().extend_from_slice(data); }
}

pub struct SniffingStream<T> {
    inner: T,
    pub state: Arc<SniffState>,
}
impl<T> SniffingStream<T> {
    pub fn new(inner: T, state: Arc<SniffState>) -> Self { Self { inner, state } }
}
impl<T: AsyncRead + Unpin> AsyncRead for SniffingStream<T> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>)
        -> Poll<std::io::Result<()>> {
        let pre = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &r {
            let filled = &buf.filled()[pre..];
            if !filled.is_empty() { self.state.push_rx(filled); }
        }
        r
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for SniffingStream<T> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8])
        -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = r { if n > 0 { self.state.push_tx(&data[..n]); } }
        r
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
