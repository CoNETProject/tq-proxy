"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const child_process_1 = require("child_process");
const iptables = (remoteAddress, proxyPORT, CallBack) => {
    return (0, child_process_1.exec)(`iptables -I INPUT 1 -s ${remoteAddress} -m tcp -p tcp --dport ${proxyPORT} -j ACCEPT`, err => {
        return CallBack(err);
    });
};
class clientFilter {
    constructor(password, listenPORT, proxyPORT) {
        this.password = password;
        this.listenPORT = listenPORT;
        this.proxyPORT = proxyPORT;
        this.startServer();
    }
    startServer() {
        const express = require('express');
        const app = express();
        const securityPath = '/' + this.password;
        app.get(securityPath, (req, res) => {
            const _ipaddress = req.socket.remoteAddress.split(':');
            const ipaddress = _ipaddress[_ipaddress.length - 1];
            return iptables(ipaddress, this.proxyPORT, err => {
                if (err) {
                    return res.end(`System Iptables Error!\n${err.message}`);
                }
                return res.end(`Your IP address [${ipaddress}] success!\n`);
            });
        });
        app.get('*', () => {
        });
        app.listen(this.listenPORT, () => {
            return console.table([
                { 'QTGate IP address filter server start at': `http://localhost:${this.listenPORT}/${this.password}` }
            ]);
        });
    }
}
exports.default = clientFilter;
