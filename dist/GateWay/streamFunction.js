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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.blockRequestData = void 0;
const Stream = __importStar(require("stream"));
const httpProxy_1 = __importDefault(require("./httpProxy"));
const log_1 = require("./log");
const util_1 = require("util");
class blockRequestData extends Stream.Transform {
    constructor(allowedAddress, timeout) {
        super();
        this.allowedAddress = allowedAddress;
        this.temp = Buffer.from('');
        this.startTime = new Date().getTime();
        this.timeOut = null;
        this.first = true;
        this.headers = null;
        this.part0 = '';
        if (timeout) {
            this.timeOut = setTimeout(() => {
                this.unpipe();
            }, timeout);
        }
    }
    _transform(chunk, encode, cb) {
        this.temp = Buffer.concat([this.temp, chunk], this.temp.length + chunk.length);
        if (this.temp.toString().split('\r\n\r\n').length < 2) {
            return cb();
        }
        const httpHeader = new httpProxy_1.default(this.temp);
        if (!this.part0) {
            this.part0 = this.temp.toString();
        }
        //      have not http format request
        if (!httpHeader.isHttpRequest) {
            (0, log_1.logger)('*************** SKIP unformat data **********************');
            (0, log_1.logger)((0, util_1.inspect)({ HEADER: this.part0 }, false, 3, true));
            httpHeader._parts.shift();
            this.temp = Buffer.from(httpHeader._parts.join('\r\n\r\n'), 'utf8');
            return this._transform(Buffer.from(''), encode, cb);
        }
        if (!this.allowedAddress) {
            (0, log_1.logger)((0, util_1.inspect)({ NOT_Allow_ADDRESS: this.part0 }));
            return cb(new Error('404'));
        }
        if (!httpHeader.isGet && !httpHeader.isPost) {
            console.log('************* unknow httpHeader   **********');
            (0, log_1.logger)((0, util_1.inspect)({ UnKnow_HEADER: this.part0 }, false, 3, true));
            httpHeader._parts.shift();
            this.temp = Buffer.from(httpHeader._parts.join('\r\n\r\n'), 'utf8');
            return this._transform(Buffer.from(''), encode, cb);
        }
        if (this.timeOut) {
            clearTimeout(this.timeOut);
            this.timeOut = null;
        }
        if (httpHeader.isGet) {
            if (this.first) {
                const split_space = httpHeader._parts[0].split(' ')[1];
                if (split_space === '/') {
                    (0, log_1.logger)((0, util_1.inspect)({ error: 'Have no path!', pathname: split_space, headers: httpHeader._parts }, false, 3, true));
                    return cb(new Error('200'));
                }
            }
            const ret = Buffer.from(httpHeader.Url.path.substr(1), 'base64');
            httpHeader._parts.shift();
            this.temp = Buffer.from(httpHeader._parts.join('\r\n\r\n'), 'utf8');
            this.push(ret);
            return this._transform(Buffer.from(''), encode, cb);
        }
        if (httpHeader._parts.length < 3) {
            return cb();
        }
        const ret = Buffer.from(httpHeader.PostBody, 'base64');
        if (!ret) {
            console.log('***************** POST get data ERROR ********************');
            (0, log_1.logger)((0, util_1.inspect)({ HEADER: this.part0 }, false, 3, true));
            httpHeader._parts.shift();
            httpHeader._parts.shift();
            this.temp = Buffer.from(httpHeader._parts.join('\r\n\r\n'), 'utf8');
            return this._transform(Buffer.from(''), encode, cb);
        }
        this.push(ret);
        httpHeader._parts.shift();
        httpHeader._parts.shift();
        this.temp = Buffer.from(httpHeader._parts.join('\r\n\r\n'), 'utf8');
        return this._transform(Buffer.from(''), encode, cb);
    }
}
exports.blockRequestData = blockRequestData;
