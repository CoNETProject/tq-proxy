# TQ Proxy Server

### This is the beginning of CoNET project
### now migrate to
## The new era of CoNET

### New Link here:
https://github.com/CoNET-project/CONET-Platform

## Description 概要

![multiple gateway](https://user-images.githubusercontent.com/19976150/140949990-22c6d9fe-5046-40dd-b8e2-edfe1f2f6cf4.gif)


TQ Proxy is lightweight and fast Proxy server based on NodeJS. It provide HTTP, HTTPS, SOCKS v4 & v5 proxy.
TQ Proxy splits a proxy to two parts, one is the gateway server and proxy server.
Communication between the two parts is using HTTP protocol to make a virtual tunnel that disguise the traffic looks like normal HTTP protocol, to exchanges packets. Support multiple gateway servers at the same time, which can increase bandwidth and reduce the risk of traffic monitoring.


TQ Proxy是輕量高速代理服務器，它支持 HTTP/HTTPS Proxy, Socks v4和v5。

它把一個Proxy服務器拆分成網關服務器和代理服務器二個部分,代理服務器獲取客戶端的網絡請求後，提交給網關服務器去訪問目標主機，然後回傳給代理服務器並返回客戶端。

網關服務器和代理服務器通过明碼HTTP混淆协议，建立一个實質加密的虚拟专用通道來逃避網絡審查。

TQ Proxy類似於Shadowsocks代理服務器，但TQ Proxy可同時使用多個網關服務器，以達到網絡加速和減少網關服務器被流量監控發現的風險。

![iOPN4](https://user-images.githubusercontent.com/19976150/140952713-faf12d83-46a8-4bfb-8fcd-30d7beeb928d.png)



## INSTALL 安裝
1. Install NodeJS / 安裝NodeJS

https://nodejs.org/en/


2. install TQ Proxy / 安裝TQ代理服務器
```bash
npm i @kloak-it/tq-proxy -g
```

## SETUP 設置

### Gateway Server 啟動網關服務器

Gateway1 server 網關服務器一 192.168.0.1
```bash
tq-proxy -g password1 80
```
Gateway2 server 網關服務器二 192.168.0.2
```bash
tq-proxy -g password2 80
```

### Proxy Server 啟動代理服務器

Proxy server 192.168.0.3
```bash
tq-proxy -p gateway.json 3127
```

### About gateway.json 關於gateway.json設定

Setup two gateway server for proxy server
```json
[
    { 
        "gateWayPort": 80, 
        "gateWayIpAddress":"192.168.0.1",
        "randomPassword":"password1"
    },{
        "gateWayPort": 80,
        "gateWayIpAddress":"192.168.0.2",
        "randomPassword":"password2"
    }
]
```

## Customized Dedicated Private Gateway Cluster service/訂製專屬VPN代理集群服務

<img width="1497" alt="https://www.tq-proxy.com" src="https://user-images.githubusercontent.com/19976150/140950996-98590619-e981-4631-933a-1bdab799ae65.png">


## Notice 注意事項

This version do not support UDP proxy.

當前版本代理服務器不支持UDP代理

このパージョンはUDP対応しておりませんので、ご注意してください。

## License 版權 

Copyright (c) Kloak Information Technologies Inc. All rights reserved.

Licensed under the [MIT](LICENSE) License.

The MIT License (MIT)
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
