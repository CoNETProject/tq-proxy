# TQ Proxy Server

## Description 概要

TQ Proxy is lightweight and fast Proxy server based on NodeJS. It provide HTTP, HTTPS, SOCKS v4 & v5 proxy.
TQ Proxy splits a proxy to two parts, one is the gateway server and proxy server.
Communication between the two parts is using HTTP protocol to make a virtual tunnel that disguise the traffic looks like normal HTTP protocol, to exchanges packets. Support multiple gateway servers at the same time, which can increase bandwidth and reduce the risk of traffic monitoring.

[Kloak Information Technologies Inc.](https://www.Kloak.app).

TQ Proxy 是加拿大Kloak公司開發的輕量高速代理服務器，它支持 HTTP/HTTPS Proxy, Socks v4和v5。

它把一個Proxy服務器拆分成網關服務器和代理服務器二個部分,代理服務器獲取客戶端的網絡請求後，提交給網關服務器去訪問目標主機，然後回傳給代理服務器並返回客戶端。

網關服務器和代理服務器通过明碼HTTP混淆协议，建立一个實質加密的虚拟专用通道來逃避網絡審查。

TQ Proxy類似於Shadowsocks代理服務器，但TQ Proxy可同時使用多個網關服務器，以達到網絡加速和減少網關服務器被流量監控發現的風險。

![http protocol](/resouce/iOPN4.png?raw=true)

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

## 我們提供預設置完成的iOPN網關服務器
### 可選數據中心位置
北美, 英國, 德國, 西班牙

```
1vCore 512MB    $5/month  400 Mbit/s帶寬，無限網絡流量 適合個人(建議同時設置2台以上以達到混淆流量)
2vCore 2GB      $20/month 400 Mbit/s帶寬，無限網絡流量 適合小規模公司(建議同時設置2台以上以達到混淆流量)
4vCore 8GB      $80/month 400 Mbit/s帶寬，無限網絡流量 適合小規模公司(建議同時設置2台以上以達到混淆流量)
```
請聯繫peter@Kloak.io

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