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
const Crypto = __importStar(require("crypto"));
const Url = __importStar(require("url"));
const cacheFileType = /\.jpeg$|\.html$|\.css$|\.gif$|\.js$|\.jpg$|\.png$|\.svg$|\.xml$/i;
class httpProxy {
    constructor(buffer) {
        this.buffer = buffer;
        this.text = buffer.toString('utf8');
        this._parts = this.text.split('\r\n\r\n');
        this.commandWithLine = this._parts[0].split(/\r\n/);
        let u = '{';
        for (let i = 1, k = 0; i < this.commandWithLine.length; i++) {
            const line = this.commandWithLine[i].split(': ');
            if (line.length !== 2) {
                if (/^host$/i.test(line[0]))
                    continue;
                break;
            }
            if (k++ !== 0)
                u += ',';
            u += `"${line[0].toLowerCase()}": ${JSON.stringify(line[1])}`;
        }
        u += '}';
        this.headers = JSON.parse(u);
    }
    get parts() {
        return Math.round(this._parts.length / 2);
    }
    get nextPart() {
        const part = '\r\n\r\n';
        if (this.parts > 1) {
            const part1 = this.text.indexOf(part);
            const part2 = this.text.indexOf(part, part1 + 1);
            const kk = this.buffer.slice(part2 + 4);
            if (kk.length)
                return kk;
        }
        return Buffer.alloc(0);
    }
    get isHttps() {
        return (this.isConnect && this.Url.port === '443');
    }
    get isHttpRequest() {
        return (/^connect|^get|^put|^delete|^post|^OPTIONS|^HEAD|^TRACE/i.test(this.commandWithLine[0]));
    }
    get command() {
        return this.commandWithLine;
    }
    get Url() {
        let http = this.commandWithLine[0].split(' ')[1];
        http = !/^http/i.test(http) ? 'http://' + http : http;
        return Url.parse(http);
    }
    get isConnect() {
        return (/^connect /i.test(this.commandWithLine[0]));
    }
    get isGet() {
        return /^GET /i.test(this.commandWithLine[0]);
    }
    get isPost() {
        return /^port/i.test(this.commandWithLine[0]);
    }
    get host() {
        return this.headers['host'].split(':')[0];
    }
    get cachePath() {
        if (!this.isGet || !this.isCanCacheFile)
            return null;
        return Crypto.createHash('md5').update(this.Url.host + this.Url.href).digest('hex');
    }
    get isCanCacheFile() {
        return cacheFileType.test(this.commandWithLine[0].split(' ')[1]);
    }
    get getProxyAuthorization() {
        for (let i = 1; i < this.commandWithLine.length; i++) {
            const y = this.commandWithLine[i];
            if (/^Proxy-Authorization: Basic /i.test(y)) {
                const n = y.split(' ');
                if (n.length === 3) {
                    return Buffer.from(n[2], 'base64').toString();
                }
                return;
            }
        }
        return;
    }
    get BufferWithOutKeepAlife() {
        if (!this.isGet || !this.isCanCacheFile)
            return this.buffer;
        let ss = '';
        this.commandWithLine.forEach(n => {
            ss += n.replace('keep-alive', 'close') + '\r\n';
        });
        ss += '\r\n\r\n';
        return Buffer.from(ss);
    }
    get Body() {
        const length = parseInt(this.headers['content-length']);
        if (!length)
            return null;
        const body = this._parts[1];
        if (body && body.length && body.length === length)
            return body;
        return null;
    }
    get preBodyLength() {
        const body = this._parts[1];
        return body.length;
    }
    get Port() {
        //console.log ( this.commandWithLine )
        const uu = this.commandWithLine[0].split(/\/\//);
        if (uu.length > 1) {
            const kk = uu[1].split(':');
            if (kk.length > 1) {
                const ret = kk[1].split(' ')[0];
                console.log(`ret = [${ret}]`);
                return parseInt(ret);
            }
            return 80;
        }
        const vv = this.commandWithLine[0].split(':');
        if (vv.length > 1) {
            const kk = vv[1].split(' ')[0];
            return parseInt(kk);
        }
        return 443;
    }
    get BodyLength() {
        return parseInt(this.headers['content-length']);
    }
}
exports.default = httpProxy;
