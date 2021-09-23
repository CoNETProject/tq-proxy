"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.logger = void 0;
const logger = (...argv) => {
    const date = new Date();
    let dateStrang = `[Gateway ${date.getHours()}:${date.getMinutes()}:${date.getSeconds()}:${date.getMilliseconds()}] `;
    return console.log(dateStrang, ...argv);
};
exports.logger = logger;
