#!/usr/bin/env node

"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const cluster_1 = require("cluster");
const makeWork = () => {
    const worker = cluster_1.fork();
    worker.once('exit', () => {
        const date = new Date();
        console.log(date.toISOString(), `Cluster Worker exit! create Work again!`);
        return makeWork();
    });
};

const util_1 = require ( "util" );
const { logger } = require("./dist/GateWay/log");
const [,,...args] = process.argv;
const setup = require ('./package.json')


let gateway = false;
let proxy = false;

const printUsage = () => {
    console.error (`qtgate server version ${ setup.version }\nGateway usage: qtgate-server -g password port\nProxy server usage: qtgate-server -p gatewayFileName.json proxyPort [listenPORT] [listenPath] \n` );
    process.exit (0);
}

const checkIptables = () => {
    if ( process.platform !== 'linux' ) {
        return false;
    }
    return true;
};
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


if ( !args[0] || !args[1]) {
    printUsage ();
}

if ( args[0] === '-g' ) {
	if (cluster_1.isPrimary) {
		makeWork();
	} else {
		const server = require('./dist/GateWay/qtGate_httpServer');
    	new server.ssModeV1 ( args [2], args [1]);
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
    const server = new proxyServer.proxyServer ( args[2], gateway );
    setTimeout (() => {
        logger(`Doing close now!`);
        server.close (()=> {
            logger(`proxy close!`);
        })
    }, 1000 * 15)
		
}