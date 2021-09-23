"use strict";
/*!
 * Copyright 2018 CoNET Technology Inc. All Rights Reserved.
 *
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
exports.sockt4 = exports.socks5 = void 0;
const Rfc1928 = __importStar(require("./rfc1928"));
const res = __importStar(require("./res"));
const Crypto = __importStar(require("crypto"));
const client_1 = require("./client");
const Util = __importStar(require("util"));
//	socks 5 headers
const server_res = {
    NO_AUTHENTICATION_REQUIRED: Buffer.from('0500', 'hex')
};
const isSslFromBuffer = (buffer) => {
    const ret = /^\x16\x03|^\x80/.test(buffer);
    return ret;
};
class socks5 {
    constructor(socket, agent, proxyServer) {
        this.socket = socket;
        this.agent = agent;
        this.proxyServer = proxyServer;
        this.host = null;
        this.ATYP = null;
        this.port = null;
        this.cmd = null;
        this.targetIpV4 = null;
        this.targetDomainData = null;
        this.keep = false;
        this.clientIP = this.socket.remoteAddress.split(':')[3] || this.socket.remoteAddress;
        //console.log (`new socks 5`)
        this.socket.once('data', (chunk) => {
            return this.connectStat2(chunk);
        });
        this.socket.write(server_res.NO_AUTHENTICATION_REQUIRED);
        this.socket.resume();
    }
    closeSocks5(buffer) {
        //console.log (`close proxy socket!`)
        if (this.socket) {
            if (this.socket.writable) {
                this.socket.end(buffer);
            }
            if (typeof this.socket.removeAllListeners === 'function')
                this.socket.removeAllListeners();
        }
    }
    connectStat3(data) {
        const CallBack = (err, _data) => {
            if (err) {
                if (this.proxyServer.useGatWay && _data && _data.length && this.socket.writable && this.proxyServer.gateway) {
                    const uuuu = {
                        uuid: Crypto.randomBytes(10).toString('hex'),
                        host: this.host || this.targetIpV4,
                        buffer: _data.toString('base64'),
                        cmd: Rfc1928.CMD.CONNECT,
                        ATYP: Rfc1928.ATYP.IP_V4,
                        port: this.port,
                        ssl: isSslFromBuffer(_data)
                    };
                    //console.log ( Util.inspect ( uuuu ))
                    //console.log (`doing gateway.requestGetWay ssl [${ uuuu.ssl }][${ uuuu.host }:${ uuuu.port }] cmd [${ uuuu.cmd }]`)
                    const id = `[${this.clientIP}:${this.port}][${Util.inspect(uuuu)}] `;
                    return this.proxyServer.gateway.requestGetWay(id, uuuu, this.agent, this.socket);
                }
                console.log(`SOCK5 ! this.proxyServer.gateway STOP socket`);
                return this.socket.end(res.HTTP_403);
            }
            return;
        };
        this.socket.once('data', (_data) => {
            //			gateway shutdown
            if (!this.proxyServer.gateway) {
                //console.log (`SOCK5 !this.proxyServer.gateway STOP sokcet! res.HTTP_403`)
                return this.socket.end(res._HTTP_PROXY_302());
            }
            (0, client_1.tryConnectHost)(this.host || this.targetIpV4, this.targetDomainData, this.port, _data, this.socket, false, this.proxyServer.checkAgainTimeOut, this.proxyServer.connectHostTimeOut, this.proxyServer.useGatWay, CallBack);
        });
        data.REP = Rfc1928.Replies.GRANTED;
        return this.socket.write(data.buffer);
    }
    connectStat2_after(retBuffer) {
        if (this.ATYP === Rfc1928.ATYP.DOMAINNAME) {
            this.targetDomainData = this.proxyServer.domainListPool.get(this.host);
        }
        else {
            this.targetDomainData = { dns: [{ family: 4, address: this.targetIpV4, expire: null, connect: [] }], expire: null };
        }
        //			gateway shutdown
        if (!this.proxyServer.gateway) {
            return this.connectStat3(retBuffer);
        }
        return (0, client_1.checkDomainInBlackList)(this.proxyServer.domainBlackList, this.host || this.targetIpV4, (err, result) => {
            if (result) {
                console.log(`host [${this.host}] Blocked!`);
                retBuffer.REP = Rfc1928.Replies.CONNECTION_NOT_ALLOWED_BY_RULESET;
                return this.closeSocks5(retBuffer.buffer);
            }
            if (this.host && !this.proxyServer.useGatWay) {
                return (0, client_1.isAllBlackedByFireWall)(this.host, false, this.proxyServer.gateway, this.agent, this.proxyServer.domainListPool, (err, _hostIp) => {
                    if (err) {
                        console.log(`host [${this.host}] Blocked!`);
                        retBuffer.REP = Rfc1928.Replies.CONNECTION_NOT_ALLOWED_BY_RULESET;
                        return this.closeSocks5(retBuffer.buffer);
                    }
                    if (!_hostIp) {
                        console.log('isAllBlackedByFireWall back no _hostIp');
                        retBuffer.REP = Rfc1928.Replies.HOST_UNREACHABLE;
                        return this.closeSocks5(retBuffer.buffer);
                    }
                    this.proxyServer.domainListPool.set(this.host, _hostIp);
                    this.targetDomainData = _hostIp;
                    return this.connectStat3(retBuffer);
                });
            }
            return this.connectStat3(retBuffer);
        });
    }
    /*
    private udpProcess ( data: Rfc1928.Requests ) {
        data.REP = Rfc1928.Replies.GRANTED
        return this.socket.write ( data.buffer )
    }
    */
    connectStat2(data) {
        const req = new Rfc1928.Requests(data);
        this.ATYP = req.ATYP;
        this.host = req.domainName;
        this.port = req.port;
        this.cmd = req.cmd;
        this.targetIpV4 = req.ATYP_IP4Address;
        //.serverIP = this.socket.localAddress.split (':')[3]
        //		IPv6 not support!
        switch (this.cmd) {
            case Rfc1928.CMD.CONNECT: {
                //console.log (`sock5 [${ this.host }]`)
                this.keep = true;
                break;
            }
            case Rfc1928.CMD.BIND: {
                console.log(`Rfc1928.CMD.BIND request data[${data.toString('hex')}]`);
                break;
            }
            case Rfc1928.CMD.UDP_ASSOCIATE: {
                this.keep = true;
                console.log(`Rfc1928.CMD.UDP_ASSOCIATE data[${data.toString('hex')}]`);
                break;
            }
            default:
                break;
        }
        //			IPv6 not support 
        if (req.IPv6) {
            this.keep = false;
        }
        if (!this.keep) {
            req.REP = Rfc1928.Replies.COMMAND_NOT_SUPPORTED_or_PROTOCOL_ERROR;
            return this.closeSocks5(req.buffer);
        }
        if (this.cmd === Rfc1928.CMD.UDP_ASSOCIATE) {
            return console.log('this.cmd === Rfc1928.CMD.UDP_ASSOCIATE skip!');
        }
        return this.connectStat2_after(req);
    }
}
exports.socks5 = socks5;
class sockt4 {
    constructor(socket, buffer, agent, proxyServer) {
        this.socket = socket;
        this.buffer = buffer;
        this.agent = agent;
        this.proxyServer = proxyServer;
        this.req = new Rfc1928.socket4Requests(this.buffer);
        this.host = this.req.domainName;
        this.port = this.req.port;
        this.cmd = this.req.cmd;
        this.targetIpV4 = this.req.targetIp;
        this.targetDomainData = null;
        this.clientIP = this.socket;
        this.keep = false;
        console.log(`new socks 4`);
        switch (this.cmd) {
            case Rfc1928.CMD.CONNECT: {
                this.keep = true;
                break;
            }
            case Rfc1928.CMD.BIND: {
                console.log('establish a TCP/IP port binding');
                console.log(this.req.buffer.toString('hex'));
                break;
            }
            case Rfc1928.CMD.UDP_ASSOCIATE: {
                console.log('associate a UDP port');
                console.log(this.req.buffer.toString('hex'));
                break;
            }
            default:
                break;
        }
        if (!this.keep) {
            this.socket.end(this.req.request_failed);
            return;
        }
        this.socket.pause();
        this.connectStat1();
    }
    connectStat2() {
        const CallBack = (err, _data) => {
            if (err) {
                if (this.proxyServer.useGatWay && _data && _data.length && this.socket.writable && this.proxyServer.gateway) {
                    const uuuu = {
                        uuid: Crypto.randomBytes(10).toString('hex'),
                        host: this.host || this.targetIpV4,
                        buffer: _data.toString('base64'),
                        cmd: Rfc1928.CMD.CONNECT,
                        ATYP: Rfc1928.ATYP.IP_V4,
                        port: this.port,
                        ssl: isSslFromBuffer(_data)
                    };
                    const id = `[${this.clientIP}:${this.port}][${uuuu.uuid}] `;
                    return this.proxyServer.gateway.requestGetWay(id, uuuu, this.agent, this.socket);
                }
                console.log(`SOCK4 connectStat2 this.proxyServer.gateway === null`);
                return this.socket.end(res.HTTP_403);
            }
            return;
        };
        this.socket.once('data', (_data) => {
            console.log(`connectStat2 [${this.host || this.targetIpV4}]get data `);
            if (!this.proxyServer.gateway) {
                console.log(`SOCK4 !this.proxyServer.gateway STOP sokcet! res.HTTP_403`);
                this.socket.end(res._HTTP_PROXY_302());
            }
            (0, client_1.tryConnectHost)(this.host, this.targetDomainData, this.port, _data, this.socket, false, this.proxyServer.checkAgainTimeOut, this.proxyServer.connectHostTimeOut, this.proxyServer.useGatWay, CallBack);
        });
        const buffer = this.req.request_4_granted(!this.host ? null : this.targetDomainData.dns[0].address, this.port);
        this.socket.write(buffer);
        return this.socket.resume();
    }
    connectStat1() {
        if (this.host) {
            this.targetDomainData = this.proxyServer.domainListPool.get(this.host);
        }
        //		gateway server shutdoan
        if (!this.proxyServer.gateway) {
            return this.connectStat2();
        }
        return (0, client_1.checkDomainInBlackList)(this.proxyServer.domainBlackList, this.host || this.targetIpV4, (err, result) => {
            if (result) {
                console.log(`[${this.host}] Blocked!`);
                return this.socket.end(this.req.request_failed);
            }
            if (this.host && !this.proxyServer.useGatWay) {
                console.log(`socks4 host [${this.host}]`);
                return (0, client_1.isAllBlackedByFireWall)(this.host, false, this.proxyServer.gateway, this.agent, this.proxyServer.domainListPool, (err, _hostIp) => {
                    if (err) {
                        console.log(`[${this.host}] Blocked!`);
                        return this.socket.end(this.req.request_failed);
                    }
                    if (!_hostIp) {
                        console.log('isAllBlackedByFireWall back no _hostIp');
                        return this.socket.end(this.req.request_failed);
                    }
                    this.proxyServer.domainListPool.set(this.host, _hostIp);
                    this.targetDomainData = _hostIp;
                    return this.connectStat2();
                });
            }
            console.log(`socks4 ipaddress [${this.targetIpV4}]`);
            return this.connectStat2();
        });
    }
}
exports.sockt4 = sockt4;
/*
export class UdpDgram {
    private server: Dgram.Socket = null
    public port = 0

    private createDgram () {
        this.server = Dgram.createSocket ( 'udp4' )
        
        this.server.once ( 'error', err => {
            console.log ( 'server.once error close server!', err  )
            this.server.close ()
        })

        this.server.on ( 'message', ( msg: Buffer, rinfo ) => {
            console.log(`UdpDgram server msg: ${ msg.toString('hex') } from ${ rinfo.address }:${ rinfo.port }`)
        })

        this.server.once ( 'listening', () => {
            const address = this.server.address()
            this.port = address.port
            console.log ( `server listening ${ address.address }:${ address.port }` )
        })

        this.server.bind ({ port: 0 } , ( err, kkk ) => {
            if ( err ) {
                return console.log ( `server.bind ERROR`, err )
            }
            console.log ( kkk )
        })
    }
    constructor () {
        this.createDgram ()
    }
}
*/ 
