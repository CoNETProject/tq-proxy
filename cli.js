#!/usr/bin/env node

"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const cluster_1 = require("cluster");

const makeWork = () => {
    const worker = cluster_1.fork();
    worker.once('exit', (code) => {
        if ( code === 3) {
            logger (`worker exit with code 3, STOP running!`)
            process.exit()
        }
        logger(`Cluster Worker exit! create Work again!`);
        return makeWork();
    });
    setTimeout (() => {
        worker.exit(0)
    }, 1000*60*60*12)

};

const util_1 = require ( "util" );
const { logger } = require("./dist/GateWay/log");
const [,,...args] = process.argv;
const setup = require ('./package.json')
let debug = false

const printUsage = () => {
    logger (`qtgate server version ${ setup.version }\nGateway usage: qtgate-server -g password port\nProxy server usage: qtgate-server -p gatewayFileName.json proxyPort [listenPORT] [listenPath] \n` );
    process.exit (0);
}

const checkIptables = () => {
    if ( process.platform !== 'linux' ) {
        return false;
    }
    return true;
};

args.forEach(n => {
    if (/\-d/.test(n)) {
        debug = true;
    };
});

const checkIPTables = ( CallBack ) => {
    if ( !checkIptables()) {
        return CallBack ( new Error ('Linux only!'))
    }
    const child_process_1 = require("child_process");
    return child_process_1.exec('which iptables', ( err, stdout, stderr ) => {
        if (err) {
            return CallBack(err);
        }
        if ( stdout ) {
            
            return CallBack ( null, true );
        }
        
        return CallBack(stderr);
    });
};


if ( !args[0] ) {
    printUsage ();
}

if ( args[0] === '-g' ) {
	if (cluster_1.isPrimary) {
		makeWork();
	} else {
		const server = require('./dist/GateWay/qtGate_httpServer');
        if ( !args [1] ) {
            const { request } = require('https');
            const options = {
                hostname: 'tq-proxy.13b995b1f.ca',
                port: 443,
                path: '/',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            };
            let data = ''
            const req = request(options, (res) => {
                res.on('data', (d) => {
                    data += d.toString();
                });

                res.once('end', () => {
                    if (!data) {
                        logger (`can't setup password`);
                        process.exit (3);
                    }
                    logger (`start gateway at port ${80} password ${ data }`);
                    return new server.ssModeV3 ( 80, data, debug, true);
                })
            })

            req.on('error', (e) => {
                console.error(e);
                process.exit (3);
            });

            return req.end();
        }
        
        
    	new server.ssModeV3 ( args [2], args [1], debug, false);
	}
    
}

if ( args[0] === '-p' ) {
    let gateway = null;
    const filename = process.cwd() + '/'+ args[1]
    try {
        gateway = require ( filename );
    } catch (ex) {
        console.log (`JSON Error! have no ${ filename }`);
        return printUsage()
    }
    
    if ( !gateway ) {
        console.log (`gateway Error! have no ./gateway.json`)
		printUsage()
    }

    if ( args[3] && args[4]) {
        checkIPTables (( err, data ) => {
            if ( err ) {
                console.log ( 'Your system have not support iptables!', err );
                return process.exit (1);
            }
            const ipFilter = require ('./dist/ProxyServer/clientIpfliter');
            new ipFilter.default ( args[4], args[3], args[2]);
            
        })
    }
   
    const proxyServer = require ('./dist/ProxyServer/client');
    const server = new proxyServer.proxyServer ( args[2], gateway, debug );

}