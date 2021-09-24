"use strict";
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
const idleHoldTime = 1000 * 60 * 30;
class container {
    constructor(client, dataOver) {
        this.client = client;
        this.dataOver = dataOver;
        this.password = this.client.randomPassword;
        this.hashPool = [];
        this.fingerprint = this.client.fingerprint;
        this.upload = 0;
        this.download = 0;
        this.idleTime = null;
        client.transferData.uploaded = client.transferData.downloaded = 0;
        this.resetIdle();
    }
    resetIdle() {
        clearTimeout(this.idleTime);
        this.idleTime = setTimeout(() => {
            console.log(`resetIdle time out!`);
            return this.dataOver();
        }, idleHoldTime);
    }
    HashCheck(data) {
        const hasdD = Crypto.createHash('md5').update(data).digest('hex');
        const index = this.hashPool.findIndex(n => { return n === hasdD; });
        if (index < 0) {
            this.hashPool.push(hasdD);
            return false;
        }
        return true;
    }
    countData(length, upload) {
        this.resetIdle();
        return upload ? this.upload += length : this.download += length;
    }
    stopContainer() {
        return this.dataOver();
    }
}
exports.default = container;
