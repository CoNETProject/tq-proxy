"use strict";
/*!
 * Copyright 2017 Vpn.Email network security technology Canada Inc. All Rights Reserved.
 *
 * Vpn.Email network technolog Canada Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ssModeV1 = void 0;
const Net = __importStar(require("net"));
const dns_1 = require("dns");
const Stream = __importStar(require("stream"));
const Compress = __importStar(require("./compress"));
const StreamFun = __importStar(require("./streamFunction"));
const fs_1 = require("fs");
const log_1 = require("./log");
const MaxAllowedTimeOut = 1000 * 60 * 60;
const blockHostFIleName = './blockHost.json';
const util_1 = require("util");
const otherRespon = (body, _status) => {
    const Ranges = (_status === 200) ? 'Accept-Ranges: bytes\r\n' : '';
    const Content = (_status === 200) ? `Content-Type: text/html; charset=utf-8\r\n` : 'Content-Type: text/html\r\n';
    const headers = `Server: nginx/1.6.2\r\n`
        + `Date: ${new Date().toUTCString()}\r\n`
        + Content
        + `Content-Length: ${body.length}\r\n`
        + `Connection: keep-alive\r\n`
        + `Vary: Accept-Encoding\r\n`
        //+ `Transfer-Encoding: chunked\r\n`
        + '\r\n';
    const status = _status === 200 ? 'HTTP/1.1 200 OK\r\n' : 'HTTP/1.1 404 Not Found\r\n';
    return status + headers + body;
};
const return404 = () => {
    const kkk = '<html>\r\n<head><title>404 Not Found</title></head>\r\n<body bgcolor="white">\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx/1.6.2</center>\r\n</body>\r\n</html>\r\n';
    return otherRespon(Buffer.from(kkk), 404);
};
const returnHome = () => {
    const kkk = `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
`;
    return otherRespon(Buffer.from(kkk), 200);
};
const dnsLookup = (hostName, CallBack) => {
    console.log(`on dnsLookup: hostName = [${hostName}]`);
    return (0, dns_1.lookup)(hostName, { all: true }, (err, data) => {
        if (err)
            return CallBack(err);
        const _buf = Buffer.from(JSON.stringify(data));
        return CallBack(null, _buf);
    });
};
class listen extends Stream.Transform {
    constructor(headString) {
        super();
        this.headString = headString;
    }
    _transform(chunk, encode, cb) {
        console.log(this.headString);
        console.log(chunk.toString('hex'));
        console.log(this.headString);
        return cb(null, chunk);
    }
}
class ssModeV1 {
    constructor(port, password) {
        this.port = port;
        this.password = password;
        this.logFileName = `qtgate_httpServer`;
        this.serverNetPool = new Map();
        this._freeDomain = [];
        this._freeIpAddress = [];
        this.hostConet = new Map();
        this.makeNewServer(port);
        try {
            this.blockList = require(blockHostFIleName);
        }
        catch (ex) {
            this.blockList = [
                { host: '42.63.21.217', error: 'connect ETIMEDOUT', port: '443', date: new Date().toISOString() },
                { host: '139.170.156.220', error: 'connect ETIMEDOUT', port: '443', date: new Date().toISOString() }
            ];
            // saveConnectErrorIPAddress ( this.blockList, err => {
            // 	if ( err ) {
            // 		console.log ( `ssModeV1 constructor saveConnectErrorIPAddress error`, err )
            // 	}
            // })
        }
    }
    makeNewServer(portNumber) {
        const serverNet = Net.createServer(socket => {
            const _remoteAddress = socket.remoteAddress;
            if (typeof _remoteAddress !== 'string') {
                (0, log_1.logger)(`socket have no _remoteAddress [${_remoteAddress}] STOP socket`);
                return socket.end();
            }
            const remoteAddress = _remoteAddress?.split(':').length > 2 ? _remoteAddress.split(':')[3] : _remoteAddress;
            const id = `[${remoteAddress}]:[${socket.remotePort}]`;
            (0, log_1.logger)(`Client ${id} connect to server!`);
            serverNet.getConnections((err, count) => {
                if (err) {
                    return (0, log_1.logger)(`serverNet.getConnections [${id}] [${portNumber}] ERROR: `, err);
                }
                return (0, log_1.logger)(`new ssMode connect [${id}:${portNumber}] opened connect=[${count}]`);
            });
            const streamFunBlock = new StreamFun.blockRequestData(true, MaxAllowedTimeOut);
            streamFunBlock.once('error', err => {
                (0, log_1.logger)(`${id} streamFunBlock on ERROR stop SOCKET!`, err.message);
                if (err.message === '200') {
                    return socket.end(returnHome());
                }
                return socket.end(return404());
            });
            const streamDecrypt = new Compress.decryptStream(id, this.password, n => {
                return;
            });
            streamDecrypt.once('error', err => {
                (0, log_1.logger)((0, util_1.inspect)({ streamDecrypt_On_ERROR: `${id}`, Headers: streamFunBlock ? streamFunBlock.headers : 'streamFunBlock have no working!' }, false, 3, true));
                return socket.end(return404());
            });
            const streamEncrypt = new Compress.encryptStream(id, this.password, 500, n => {
                return;
            }, null, () => {
                const firstConnect = new FirstConnect(socket, streamEncrypt, streamDecrypt, this._freeDomain, this._freeIpAddress, this.blockList, this.hostConet);
                firstConnect.once('error', err => {
                    (0, log_1.logger)(`[${streamFunBlock.part0}]firstConnect.on ERROR:`, err.message);
                    return socket.end(return404());
                });
                socket.pipe(streamFunBlock).pipe(streamDecrypt).pipe(firstConnect).once('error', err => {
                    console.log(`pipe on ERROR:`, err.message);
                    socket.end(return404());
                });
            });
            socket.once('end', () => {
                return serverNet.getConnections((err, count) => {
                    return console.log(`[${id}:${portNumber} ]socket.on END! connected = `, count);
                });
            });
            socket.once('unpipe', src => {
                //console.log (`[${ id }:${ portNumber }] socket.once unpipe!`)
                return socket.end();
            });
            socket.once('error', err => {
                console.log(`socket.on ERROR!`);
                return socket.end();
            });
        });
        serverNet.on('error', err => {
            return (0, log_1.logger)('ssModeV1 serverNet.on error:' + err.message);
        });
        serverNet.maxConnections = 12800;
        return serverNet.listen(portNumber, null, 2048, () => {
            const log = `SS mode start up listening on [${portNumber}]`;
            return (0, log_1.logger)(log);
        });
    }
    stopServer(portNumber) {
        const server = this.serverNetPool.get(portNumber);
        if (!server) {
            return console.log(`ssModeV1 on stopServer [${portNumber}] but ca't find!`);
        }
        return server.close();
    }
    // public freeDomain ( freeDomain: string [], freeIpAddress: string[], blockedIpaddress: string[] ) {
    // 	this._freeDomain = freeDomain
    // 	this._freeIpAddress = freeIpAddress
    // 	blockedIpaddress.forEach ( n => {
    // 		this.blockList.set ( n, true )
    // 	})
    // 	//console.log (`ssModeV1 have new freeDomain\n${ this._freeDomain }\n${ this._freeIpAddress }\n${ this.blockList }`)
    // }
    // public addBlockIpaddress ( iptables: string[]) {
    // 	iptables.forEach ( n => {
    // 		this.blockList.set ( n, true )
    // 	})
    // 	return
    // }
    addListenPort(portNumber) {
        const server = this.serverNetPool.get(portNumber);
        if (server) {
            return console.log(`addListenPort [${portNumber}] already ready!`);
        }
        return this.makeNewServer(portNumber);
    }
}
exports.ssModeV1 = ssModeV1;
const saveConnectErrorIPAddress = (blockedHost, CallBack) => {
    return (0, fs_1.writeFile)(blockHostFIleName, JSON.stringify(blockedHost), 'utf8', CallBack);
};
class FirstConnect extends Stream.Writable {
    constructor(clientSocket, encrypt, decrypt, freeDomain, freeIpaddress, blockList, hostCount) {
        super();
        this.clientSocket = clientSocket;
        this.encrypt = encrypt;
        this.decrypt = decrypt;
        this.freeDomain = freeDomain;
        this.freeIpaddress = freeIpaddress;
        this.blockList = blockList;
        this.hostCount = hostCount;
        this.socket = null;
    }
    _write(chunk, encode, cb) {
        //		first time
        if (!chunk?.length) {
            return cb(new Error(`chunk EOF!`));
        }
        if (!this.socket) {
            const _data = chunk.toString();
            let isIpv4 = false;
            let data = null;
            try {
                data = JSON.parse(_data);
            }
            catch (e) {
                console.log(`FirstConnect JSON.parse [${_data}]catch error:`, e);
                return cb(e);
            }
            if (data?.hostName?.length) {
                this.encrypt.dataCount = this.decrypt.dataCount = false;
                //console.log ( `data.host [${ data.host }] is free `)
                return dnsLookup(data.hostName, (err, data) => {
                    if (err) {
                        return cb(err);
                    }
                    this.encrypt.pipe(this.clientSocket);
                    this.encrypt.end(data);
                });
            }
            if (data.uuid) {
                this.decrypt.id += `[${data.host}:${data.port}]`;
                const hostMatch = data.host + ':' + data.port;
                console.log(`data.uuid = [${data.uuid}] target: [${hostMatch}]`);
                let hostCount = this.hostCount.get(hostMatch) || 0;
                this.hostCount.set(hostMatch, ++hostCount);
                const isBlacked = this.blockList.findIndex(n => n.host === data.host) > -1 ? true : false;
                if (isBlacked) {
                    console.log(`*************************** [${new Date().toISOString()}] [${data.host}:${data.port}] in blockList STOP it!`);
                    return cb(new Error(`[${data.host}] in blockList`));
                }
                isIpv4 = Net.isIPv4(data.host);
                // if ( isIpv4 = Net.isIPv4 ( data.host )){
                // 	if ( this.freeIpaddress.findIndex ( n => { return n === data.host }) > -1 ) {
                // 		console.log ( `IP address host [${ data.host }] is free `)
                // 		this.encrypt.dataCount = this.decrypt.dataCount = false
                // 	} else {
                // 		this.encrypt.dataCount = this.decrypt.dataCount = true
                // 		console.log ( `IP address host [${ data.host }] is NOT FREE `)
                // 	}
                // } else {
                // 	if ( this.freeDomain.findIndex ( n => { return new RegExp ( n ).test ( data.host )}) > -1 ) {
                // 		this.encrypt.dataCount = this.decrypt.dataCount = false
                // 		console.log ( `Domain host [${ data.host }] is free `)
                // 	} else {
                // 		this.encrypt.dataCount = this.decrypt.dataCount = true
                // 		//console.log ( `Domain host [${ data.host }] is NOT FREE freeDomain = ${ Util.inspect ( this.freeDomain ) }`)
                // 	}
                // }
                console.log(`Net.connect ({ port: ${data.port} , host: ${data.host}})`);
                this.socket = Net.connect({ port: data.port, host: data.host }, () => {
                    this.socket.pipe(this.encrypt).pipe(this.clientSocket);
                    this.socket.write(Buffer.from(data.buffer, 'base64'));
                    return cb();
                });
                this.socket.once('end', () => {
                    return this.end();
                });
                return this.socket.once('error', err => {
                    console.log('FirstConnect socket on error!', err.message);
                    //this.blockList.push ({ host: data.host, port: data.port, error: err.message, date: new Date().toISOString ()})
                    this.end();
                    // return saveConnectErrorIPAddress ( this.blockList, err => {
                    // 	if ( err ) {
                    // 		console.log ( `saveConnectErrorIPAddress error`, err )
                    // 	}
                    // })
                });
            }
            console.log(`data.uuid == null!`);
            return cb(new Error('unknow connect!'));
        }
        //		the next stream
        if (this.socket.writable) {
            this.socket.write(chunk);
            return cb();
        }
        return cb(new Error('FirstConnect socket.writable=false'));
    }
}
