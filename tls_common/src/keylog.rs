use std::sync::Mutex;
use rustls::KeyLog;

#[derive(Default, Debug)]
pub struct CollectKeyLog {
    inner: Mutex<Vec<String>>, // 每行: "<LABEL> <CLIENT_RANDOM_HEX> <SECRET_HEX>"
}
impl KeyLog for CollectKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let line = format!("{} {} {}",
            label, hex::encode_upper(client_random), hex::encode_upper(secret));
        self.inner.lock().unwrap().push(line);
    }
}
impl CollectKeyLog {
    pub fn lines(&self) -> Vec<String> { self.inner.lock().unwrap().clone() }
    pub fn clear(&self) { self.inner.lock().unwrap().clear(); }
}
