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
exports.Base64MediaFileStream3 = exports.encryptMediaFileStream = exports.getDecrypGatwayStreamFromHttp = exports.getDecryptClientStreamFromHttp = exports.decryptStream = exports.encryptStream = exports.openPacket = exports.packetBuffer = exports.decrypt = exports.encrypt = void 0;
const crypto = __importStar(require("crypto"));
const Async = __importStar(require("async"));
const Stream = __importStar(require("stream"));
const Fs = __importStar(require("fs"));
const EOF = Buffer.from('\r\n\r\n', 'utf8');
const child_process_1 = require("child_process");
const Uuid = __importStar(require("node-uuid"));
const encrypt = (text, masterkey, CallBack) => {
    let salt = null;
    Async.waterfall([
        next => crypto.randomBytes(64, next),
        (_salt, next) => {
            salt = _salt;
            crypto.pbkdf2(masterkey, salt, 2145, 32, 'sha512', next);
        }
    ], (err, derivedKey) => {
        if (err)
            return CallBack(err);
        crypto.randomBytes(12, (err1, iv) => {
            if (err1)
                return CallBack(err1);
            const cipher = crypto.createCipheriv('aes-256-gcm', derivedKey, iv);
            let _text = Buffer.concat([Buffer.alloc(4, 0), text]);
            _text.writeUInt32BE(text.length, 0);
            if (text.length < 500) {
                _text = Buffer.concat([_text, Buffer.alloc(100 + Math.random() * 1000)]);
            }
            const encrypted = Buffer.concat([cipher.update(_text), cipher.final()]);
            const ret = Buffer.concat([salt, iv, cipher.getAuthTag(), encrypted]);
            return CallBack(null, ret);
        });
    });
};
exports.encrypt = encrypt;
/**
 * Decrypts text by given key
 * @param String base64 encoded input data
 * @param Buffer masterkey
 * @returns String decrypted (original) text
 */
const decrypt = (data, masterkey, CallBack) => {
    if (!data || !data.length)
        return CallBack(new Error('null'));
    try {
        // base64 decoding
        // convert data to buffers
        const salt = data.slice(0, 64);
        const iv = data.slice(64, 76);
        const tag = data.slice(76, 92);
        const text = data.slice(92);
        // derive key using; 32 byte key length
        crypto.pbkdf2(masterkey, salt, 2145, 32, 'sha512', (err, derivedKey) => {
            if (err)
                return CallBack(err);
            // AES 256 GCM Mode
            try {
                const decipher = crypto.createDecipheriv('aes-256-gcm', derivedKey, iv);
                decipher.setAuthTag(tag);
                const decrypted = Buffer.concat([decipher.update(text), decipher.final()]);
                const leng = decrypted.slice(4, 4 + decrypted.readUInt32BE(0));
                return CallBack(null, leng);
            }
            catch (ex) {
                console.log(`decrypt catch error [${ex.message}]`);
            }
        });
    }
    catch (e) {
        return CallBack(e);
    }
};
exports.decrypt = decrypt;
const packetBuffer = (bit0, _serial, id, buffer) => {
    const _buffer = new Buffer(6);
    _buffer.fill(0);
    _buffer.writeUInt8(bit0, 0);
    _buffer.writeUInt32BE(_serial, 1);
    const uuid = new Buffer(id, 'utf8');
    _buffer.writeUInt8(id.length, 5);
    if (buffer && buffer.length)
        return Buffer.concat([_buffer, uuid, buffer]);
    return Buffer.concat([_buffer, uuid]);
};
exports.packetBuffer = packetBuffer;
const openPacket = (buffer) => {
    const idLength = buffer.readUInt8(5);
    return {
        command: buffer.readUInt8(0),
        serial: buffer.readUInt32BE(1),
        uuid: buffer.toString('utf8', 6, 6 + idLength),
        buffer: buffer.slice(6 + idLength)
    };
};
exports.openPacket = openPacket;
const HTTP_HEADER = Buffer.from(`HTTP/1.1 200 OK\r\nDate: ${new Date().toUTCString()}\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nVary: Accept-Encoding\r\n\r\n`, 'utf8');
const HTTP_EOF = Buffer.from('\r\n\r\n', 'utf8');
class encryptStream extends Stream.Transform {
    constructor(id, password, random, download, httpHeader, CallBack) {
        super();
        this.id = id;
        this.password = password;
        this.random = random;
        this.download = download;
        this.httpHeader = httpHeader;
        this.ERR = null;
        this.first = true;
        this.derivedKey = null;
        this.dataCount = false;
        Async.waterfall([
            next => crypto.randomBytes(64, next),
            (_salt, next) => {
                this.salt = _salt;
                crypto.randomBytes(12, next);
            },
            (_iv, next) => {
                this.iv = _iv;
                crypto.pbkdf2(password, this.salt, 2145, 32, 'sha512', next);
            }
        ], (err, derivedKey) => {
            if (err)
                return this.ERR = err;
            this.derivedKey = derivedKey;
            return CallBack(err);
        });
    }
    BlockBuffer(_buf) {
        return Buffer.from(_buf.length.toString(16).toUpperCase() + '\r\n', 'utf8');
    }
    _transform(chunk, encode, cb) {
        const cipher = crypto.createCipheriv('aes-256-gcm', this.derivedKey, this.iv);
        let _text = Buffer.concat([Buffer.alloc(4, 0), chunk]);
        _text.writeUInt32BE(chunk.length, 0);
        if (chunk.length < this.random) {
            _text = Buffer.concat([_text, Buffer.allocUnsafe(Math.random() * 1000)]);
        }
        const _buf = Buffer.concat([cipher.update(_text), cipher.final()]);
        const _buf1 = Buffer.concat([cipher.getAuthTag(), _buf]);
        if (this.dataCount) {
            //console.log ( `**** encryptStream ID[${ this.id }] dataCount is [true]! data.length`)
            this.download(_buf1.length);
        }
        if (this.first) {
            this.first = false;
            const black = Buffer.concat([this.salt, this.iv, _buf1]).toString('base64');
            if (!this.httpHeader) {
                const _buf4 = Buffer.from(black, 'utf8');
                return cb(null, Buffer.concat([HTTP_HEADER, this.BlockBuffer(_buf4), _buf4, EOF]));
            }
            return cb(null, this.httpHeader(black));
        }
        const _buf2 = _buf1.toString('base64');
        if (this.httpHeader) {
            return cb(null, this.httpHeader(_buf2));
        }
        const _buf3 = Buffer.from(_buf2, 'utf8');
        return cb(null, Buffer.concat([this.BlockBuffer(_buf3), _buf3, EOF]));
    }
}
exports.encryptStream = encryptStream;
class decryptStream extends Stream.Transform {
    constructor(id, password, upload) {
        super();
        this.id = id;
        this.password = password;
        this.upload = upload;
        this.first = true;
        this.dataCount = true;
        this.derivedKey = null;
        this.decipher = null;
    }
    firstProcess(chunk, CallBack) {
        if (chunk.length < 76) {
            return CallBack(new Error(`Unknow connect!`));
        }
        this.first = false;
        this.salt = chunk.slice(0, 64);
        this.iv = chunk.slice(64, 76);
        return crypto.pbkdf2(this.password, this.salt, 2145, 32, 'sha512', (err, derivedKey) => {
            if (err) {
                console.log(`**** decryptStream crypto.pbkdf2 ERROR: ${err.message}`);
                return CallBack(err);
            }
            this.derivedKey = derivedKey;
            const _buf = chunk.slice(76);
            try {
                this.decipher = crypto.createDecipheriv('aes-256-gcm', this.derivedKey, this.iv);
                // @ts-ignore
                this.decipher.setAuthTag(_buf.slice(0, 16));
            }
            catch (ex) {
                return CallBack(new Error(`class decryptStream firstProcess crypto.createDecipheriv Error chunk [${chunk.toString()}]`));
            }
            try {
                const _Buf = Buffer.concat([this.decipher.update(_buf.slice(16)), this.decipher.final()]);
                const length = _Buf.readUInt32BE(0) + 4;
                const uuu = _Buf.slice(4, length);
                return CallBack(null, uuu);
            }
            catch (e) {
                return CallBack(new Error(`class decryptStream firstProcess _decrypt error. chunk.length = [${chunk.length}]`));
            }
        });
    }
    _transform(chunk, encode, cb) {
        if (this.dataCount) {
            //console.log ( `decryptStream id [${ this.id }] dataCount = [TRUE]!`)
            this.upload(chunk.length);
        }
        if (this.first) {
            return this.firstProcess(chunk, cb);
        }
        this.decipher = crypto.createDecipheriv('aes-256-gcm', this.derivedKey, this.iv);
        // @ts-ignore
        this.decipher.setAuthTag(chunk.slice(0, 16));
        try {
            const _Buf = Buffer.concat([this.decipher.update(chunk.slice(16)), this.decipher.final()]);
            const length = _Buf.readUInt32BE(0) + 4;
            return cb(null, _Buf.slice(4, length));
        }
        catch (e) {
            console.log('class decryptStream _decrypt error:', e.message);
            return cb(e);
        }
    }
}
exports.decryptStream = decryptStream;
class encode extends Stream.Transform {
    constructor() {
        super();
        this.kk = null;
    }
    _transform(chunk, encode, cb) {
        let start = chunk.slice(0);
        while (start.length) {
            const point = start.indexOf(0x0a);
            if (point < 0) {
                this.push(start);
                break;
            }
            const _buf = start.slice(0, point);
            this.push(_buf);
            start = start.slice(point + 1);
        }
        return cb();
    }
}
class encodeHex extends Stream.Transform {
    constructor() { super(); }
    _transform(chunk, encode, cb) {
        return cb(null, chunk.toString('utf8'));
    }
}
class getDecryptClientStreamFromHttp extends Stream.Transform {
    constructor() {
        super();
        this.first = true;
        this.text = '';
    }
    getBlock(block) {
        const uu = block.split('\r\n');
        if (uu.length !== 2) {
            return null;
        }
        const length = parseInt(uu[0], 16);
        const text = uu[1];
        if (length === text.length) {
            return text;
        }
        console.log(`length[${length}] !== text.length [${text.length}]`);
        return null;
    }
    _transform(chunk, encode, cb) {
        this.text += chunk.toString('utf8');
        const line = this.text.split('\r\n\r\n');
        while (this.first && line.length > 1 || !this.first && line.length) {
            if (this.first) {
                this.first = false;
                line.shift();
            }
            const _text = line.shift();
            if (!_text.length)
                continue;
            const text = this.getBlock(_text);
            if (!text) {
                //			middle data can't get block
                if (line.length) {
                    console.log('getDecryptStreamFromHttp have ERROR:\n*****************************\n');
                    console.log(text);
                    return this.unpipe();
                }
                this.text = _text;
                return cb();
            }
            this.push(Buffer.from(text, 'base64'));
        }
        this.text = '';
        return cb();
    }
}
exports.getDecryptClientStreamFromHttp = getDecryptClientStreamFromHttp;
class getDecrypGatwayStreamFromHttp extends Stream.Transform {
    constructor(saveLog) {
        super();
        this.saveLog = saveLog;
        this.text = '';
    }
    formatErr(text) {
        const log = 'getDecryptRequestStreamFromHttp format ERROR:\n*****************************\n' + text + '\r\n';
        console.log(log);
        this.saveLog(log);
    }
    _transform(chunk, encode, cb) {
        this.text += chunk.toString('utf8');
        const block = this.text.split('\r\n\r\n');
        while (block.length > 1) {
            const blockText = block.shift();
            if (!blockText.length)
                continue;
            if (/^GET /i.test(blockText)) {
                const _line = blockText.split('\r\n')[0];
                const _url = _line.split(' ');
                if (_url.length < 2) {
                    if (block.length > 1) {
                        this.formatErr(blockText);
                        return this.unpipe();
                    }
                    this.text = blockText;
                    return cb();
                }
                const text = Buffer.from(_url[1].slice(1), 'base64');
                this.push(text);
                continue;
            }
            if (/^POST /i.test(blockText)) {
                if (block.length > 0) {
                    const header = blockText.split('\r\n');
                    const _length = header.findIndex(n => {
                        return /^Content-Length: /i.test(n);
                    });
                    if (_length === -1) {
                        this.formatErr(blockText);
                        return this.unpipe();
                    }
                    const lengthString = header[_length].split(' ');
                    if (lengthString.length !== 2) {
                        this.formatErr(blockText);
                        return this.unpipe();
                    }
                    const length = parseInt(lengthString[1]);
                    if (!length) {
                        this.formatErr(blockText);
                        return this.unpipe();
                    }
                    const _text = block.shift();
                    if (length !== _text.length) {
                        const log = `${blockText}\r\n\r\n${_text}`;
                        if (block.length > 0) {
                            this.formatErr(log);
                            return this.unpipe();
                        }
                        this.text = log;
                        return cb();
                    }
                    this.push(Buffer.from(_text, 'base64'));
                    continue;
                }
                this.text = blockText;
                return cb();
            }
        }
        this.text = block[0];
        return cb();
    }
}
exports.getDecrypGatwayStreamFromHttp = getDecrypGatwayStreamFromHttp;
const tenMbyte = 10240000;
class saveBlockFile extends Stream.Writable {
    constructor(fileName, data) {
        super();
        this.fileName = fileName;
        this.data = data;
        this.length = 0;
        this.fileAddTag = 0;
        this._chunk = Buffer.allocUnsafe(0);
    }
    _write(chunk, encode, callback) {
        this.length += chunk.length;
        this._chunk = Buffer.concat([this._chunk, chunk]);
        if (this.length < tenMbyte) {
            return callback();
        }
        const cipher = crypto.createCipheriv(this.data.algorithm, this.data.derivedKey, this.data.iv);
        const _data = Buffer.concat([cipher.update(this._chunk), cipher.final()]);
        const fileName = this.fileName + '.' + this.fileAddTag++;
        this.data.files.push(fileName);
        // @ts-ignore
        this.data.getAuthTag.push(cipher.getAuthTag().toString('base64'));
        return Fs.writeFile(fileName, this._chunk.toString('base64'), err => {
            this._chunk = Buffer.allocUnsafe(0);
            this.length = 0;
            if (err) {
                return callback(err);
            }
            return callback();
        });
    }
}
const encryptMediaFileStream = (fileName, password, CallBack) => {
    let enCryptoData = {
        salt: null,
        iv: null,
        iterations: 100000,
        keylen: 32,
        digest: 'sha512',
        derivedKey: null,
        algorithm: 'aes-256-gcm',
        files: [],
        getAuthTag: []
    };
    let cipher = null;
    Async.waterfall([
        next => crypto.randomBytes(64, next),
        (_salt, next) => {
            enCryptoData.salt = _salt;
            crypto.randomBytes(12, next);
        },
        (_iv, next) => {
            enCryptoData.iv = _iv;
            crypto.pbkdf2(password, enCryptoData.salt, enCryptoData.iterations, enCryptoData.keylen, enCryptoData.digest, next);
        }
    ], (err, derivedKey) => {
        if (err) {
            return CallBack(err);
        }
        enCryptoData.derivedKey = derivedKey;
        const readFile = Fs.createReadStream(fileName);
        const writeFile = new saveBlockFile(fileName, enCryptoData);
        readFile.once('close', () => {
            console.log(`readFile.once close`);
            return CallBack(null, enCryptoData);
        });
        readFile.pipe(writeFile);
    });
};
exports.encryptMediaFileStream = encryptMediaFileStream;
const addHeaderForBase64File = (addText, fileName, CallBack) => {
    const tempFile = 'temp/' + Uuid.v4();
    const cmd = `echo -n '${addText}' | cat - ${fileName} > ${tempFile} && echo -n "\r\n\r\n" >> ${tempFile} && mv -f  ${tempFile}  ${fileName} `;
    return (0, child_process_1.exec)(cmd, CallBack);
};
const Base64MediaFileStream3 = (fileName, domainName, CallBack) => {
    const text = `Content-Type: application/octet-stream\r\nContent-Disposition: attachment\r\nMessage-ID:<${Uuid.v4()}@>${domainName}\r\nContent-Transfer-Encoding: base64\r\nMIME-Version: 1.0\r\n\r\n`;
    const cmd = `base64 ${fileName} | split -b 10MB -d  --verbose - ${fileName}. | sed "s/creating file '//g" | sed "s/'//g" `;
    Async.series([
        next => (0, child_process_1.exec)(cmd, next),
        next => (0, child_process_1.exec)(`rm ${fileName}`, next)
    ], (err, data) => {
        if (err) {
            return CallBack(err);
        }
        const files = data[0][0].split('\n');
        if (!files[files.length - 1].length) {
            files.pop();
        }
        return Async.eachSeries(files, (n, next) => {
            return addHeaderForBase64File(text, n, next);
        }, err => {
            return CallBack(null, files);
        });
    });
};
exports.Base64MediaFileStream3 = Base64MediaFileStream3;
