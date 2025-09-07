## 开发日志

9.5 尝试中...

9.7 更新，基本完成了，还剩下从握手协商过程中回调得到通信过程的参数，以及对参数和流程的可视化



# 一些可用的命令示例
> 注意，本次实验中两台电脑
> 在 tj-wifi 中的 ip 地址分别为：100.80.54.17，100.80.44.23
> 在个人热点中的 ip 地址分别为：172.20.10.7，172.20.10.6
> （在当时的实验环境中是这样，不过 DHCP 分配的 ip 地址可能会随时变化）
> 另外，服务器的证书在客户端 ip 地址更新时需要同步更新：在调用证书生成器时，在其中的 ip-addresses 参数后面加上新客户端的 ip 地址（或直接替换）



### 自签名证书生成

```terminal
cargo run --package tls_common --bin cert-generator --features cert-gen -- self-signed --ca-common-name "My TLS CA" --out-cert ./ca.crt --out-key ./ca_key/ca.key
```



### 使用自签名证书来生成客户端或服务器证书

    服务器
```terminal
cargo run --package tls_common --bin cert-generator --features cert-gen -- sign --ca-name "ca" --common-name server.tls --dns-names "localhost,www.mytlsapp.test" --ip-addresses "172.20.10.7,100.80.54.17,127.0.0.1,::1" --is-server --out-cert ./server/server.crt --out-key ./server/server.key
```
    客户端
```terminal
cargo run --package tls_common --bin cert-generator --features cert-gen -- sign --ca-name ca --common-name user-wyn --is-client --out-cert ./client/client.crt --out-key ./client/client.key
```



### 使用openssl验证生成的证书

```terminal
openssl verify -CAfile ./ca.crt ./ca.crt # 验证ca自签名证书

openssl verify -CAfile ./ca.crt ./server/server.crt # 用自签名ca验证服务器证书
```

