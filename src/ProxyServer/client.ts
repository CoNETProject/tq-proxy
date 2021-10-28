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

import * as Net from 'net'
import * as Http from 'http'
import HttpProxyHeader from './httpProxy'
import * as Crypto from 'crypto'
import * as res from './res'
import * as Fs from 'fs'
import * as Path from 'path'
import * as Socks from './socket5ForiOpn'
import gateWay from './gateway'
import * as Os from 'os'
import { logger } from '../GateWay/log'
import colors from 'colors/safe'
import { inspect } from 'util'

const whiteIpFile = 'whiteIpList.json'
Http.globalAgent.maxSockets = 1024
const ipConnectResetTime = 1000 * 60 * 5



let flag = 'w'

const QTGateFolder = Path.join ( Os.homedir(), '.QTGate' )
const proxyLogFile = Path.join ( QTGateFolder, 'proxy.log' )

const saveLog = ( log: string ) => {
	const data = `${ new Date().toUTCString () }: ${ log }\r\n`
	Fs.appendFile ( proxyLogFile, data, { flag: flag }, err => {
		flag = 'a'
	})
}

/**
 * 			IPv6 support!
 */
const hostGlobalIpV6 = false

const testGatewayDomainName = 'www.google.com'


const closeClientSocket = ( socket: Net.Socket, status: number = 404) => {
	if ( !socket || ! socket.writable )
		return
	let stat = res._HTTP_404
	switch ( status ) {
		case 502:
			stat = res._HTTP_502
			break;
		case 599:
			stat = res._HTTP_599
			break;
		case 598:
			stat = res._HTTP_598
			break;
		case -200:
			stat = res._HTTP_PROXY_200
			socket.write ( stat )
			return socket.resume ()
		default:
			break;
	}
	return socket.end ( stat )
	
}


export const getSslConnectFirstData = ( clientSocket: Net.Socket, data: Buffer, first: boolean, CallBack ) => {
	if ( first ) {
		clientSocket.once ( 'data', ( _data: Buffer ) => {
			return getSslConnectFirstData ( clientSocket, _data, false, CallBack )
		})
		return closeClientSocket ( clientSocket, -200 )
	}
		
	return CallBack (null, data )
	
}

export const isAllBlackedByFireWall = ( hostName: string, ip6: boolean, gatway: gateWay, userAgent: string, domainListPool: Map < string, domainData >,
	CallBack: ( err?: Error, hostIp?: domainData ) => void ) => {

	const hostIp = domainListPool.get ( hostName )
	const now = new Date ().getTime ()
	if ( ! hostIp || hostIp.expire < now )
		return  gatway.hostLookup ( hostName, userAgent, ( err, ipadd ) => {
			return CallBack ( err, ipadd )
		})
	return CallBack ( null, hostIp )
}

const isSslFromBuffer = ( buffer ) => {

	const ret = /^\x16\x03|^\x80/.test ( buffer )
	return ret
}


const httpProxy = ( clientSocket: Net.Socket, buffer: Buffer, _gatway: gateWay, debug: boolean ) => {

	if ( !_gatway || typeof _gatway.requestGetWay !== 'function' ) {
		console.log (colors.red(`httpProxy !gateWay stop SOCKET res._HTTP_PROXY_302 `))
		return clientSocket.end ( res._HTTP_PROXY_302 ())
	}
		
	const httpHead = new HttpProxyHeader ( buffer )
	const hostName = httpHead.host
	const userAgent = httpHead.headers [ 'user-agent' ]


	const connect = ( _, _data?: Buffer ) => {
		const uuuu : VE_IPptpStream = {
			uuid: Crypto.randomBytes (10).toString ('hex'),
			host: hostName,
			hostIPAddress: httpHead.hostIpAddress,
			buffer: _data.toString ( 'base64' ),
			cmd: httpHead.methods,
			//ATYP: Rfc1928.ATYP.IP_V4,
			port: httpHead.Port,
			ssl: isSslFromBuffer ( _data )
		}

		const requestObj: requestObj = {
			remotePort: clientSocket.remotePort,
			remoteAddress: clientSocket.remoteAddress.split(':')[3],
			targetHost: hostName,
			targetPort: httpHead.Port,
			methods: httpHead.methods,
			uuid: uuuu.uuid
		}

		if (!_data || ! _data.length) {
			console.log( colors.red(`httpProxy got unknow request stop proxy request `))
			closeClientSocket(clientSocket)
			return console.log( inspect( requestObj, false, 3, true ))
		}

		if ( _gatway && typeof _gatway.requestGetWay === 'function' ) {
			return _gatway.requestGetWay ( requestObj, uuuu, userAgent, clientSocket )
		}
		console.log (colors.red(`httpProxy _gatway have no ready!`))
		return closeClientSocket(clientSocket)
	}

	if ( httpHead.isConnect ) {
		return getSslConnectFirstData ( clientSocket, buffer, true, connect )
	}
	return connect (null, buffer )
	

}

const getPac = ( hostIp: string, port: string, http: boolean, sock5: boolean ) => {

	const FindProxyForURL = `function FindProxyForURL ( url, host )
	{
		if ( isInNet ( dnsResolve( host ), "0.0.0.0", "255.0.0.0") ||
		isInNet( dnsResolve( host ), "172.16.0.0", "255.240.255.0") ||
		isInNet( dnsResolve( host ), "127.0.0.0", "255.255.255.0") ||
		isInNet ( dnsResolve( host ), "192.168.0.0", "255.255.0.0" ) ||
		isInNet ( dnsResolve( host ), "10.0.0.0", "255.0.0.0" )) {
			return "DIRECT";
		}
		return "${ http ? 'PROXY': ( sock5 ? 'SOCKS5' : 'SOCKS' ) } ${ hostIp }:${ port }";
	
	}`
	//return "${ http ? 'PROXY': ( sock5 ? 'SOCKS5' : 'SOCKS' ) } ${ hostIp }:${ port.toString() }; ";
	return res.Http_Pac ( FindProxyForURL )
}

export class proxyServer {
	private hostLocalIpv4: { network: string, address: string } []= []
	private hostLocalIpv6: string = null
	private hostGlobalIpV4: string = null
	private hostGlobalIpV6: string = null
	private network = false
	private getGlobalIpRunning = false
	private server: Net.Server = null
	public gateway = new gateWay ( this.multipleGateway, this.debug )
	public whiteIpList = []
	public domainBlackList = []
	public domainListPool = new Map ()
	public checkAgainTimeOut = 1000 * 60 * 5
	public connectHostTimeOut = 1000 * 5
	public useGatWay = true
	public clientSockets: Set<Net.Socket> = new Set() 
	
	private saveWhiteIpList () {
		if ( this.whiteIpList.length > 0 ) {
			Fs.writeFile ( Path.join( __dirname, whiteIpFile ), JSON.stringify( this.whiteIpList ), { encoding: 'utf8' }, err => {
				if ( err ) {
					return console.log ( `saveWhiteIpList save file error : ${ err.message }`)
				}
			})
		}

	}

	private getGlobalIp = ( gateWay: gateWay ) => {
		if ( this.getGlobalIpRunning ) {
			return console.log (`getGlobalIp getGlobalIpRunning === true!, skip!`)
		}
			
		this.getGlobalIpRunning = true
		logger ( `doing getGlobalIp!`)
		return gateWay.hostLookup ( testGatewayDomainName, null, ( err, data ) => {
			this.getGlobalIpRunning = false
			if ( err ) {
				return logger ( 'getGlobalIp ERROR:', err.message )
			}
				
			//console.log ( Util.inspect ( data ))
			
			this.hostLocalIpv6 ? console.log ( `LocalIpv6[ ${ this.hostLocalIpv6 } ]`) : null

			this.hostLocalIpv4.forEach ( n => {
				return console.log ( `LocalIpv4[ ${ n.address }]`)
			})

			this.hostGlobalIpV6 ? console.log ( `GlobalIpv6[ ${ this.hostGlobalIpV6 } ]`) : null
			
			this.hostGlobalIpV4 ? console.log ( `GlobalIpv4[ ${ this.hostGlobalIpV4 } ]`) : null

			const domain = data
			if ( ! domain ) {
				return console.log ( `[] Gateway connect Error!` )
			}
			this.network = true
			console.log ( '*************** Gateway connect ready *************************' )

		})

	}
    
	constructor ( 
		public proxyPort: string,						//			Proxy server listening port number
		private multipleGateway: IConnectCommand[],	 	//			gateway server information
		public debug = false
		) {
			logger (colors.blue(`proxyServer startup debug [${ debug }]`))
			this.getGlobalIp ( this.gateway )
			let socks = null
			
			this.server = Net.createServer ( socket => {
				const ip = socket.remoteAddress
				this.clientSockets.add (socket)
				const isWhiteIp = this.whiteIpList.find ( n => { return n === ip }) ? true : false
				let agent = 'Mozilla/5.0'
					//	windows 7 GET PAC User-Agent: Mozilla/5.0 (compatible; IE 11.0; Win32; Trident/7.0)

				//		proxy auto setup support
				socket.once ( 'data', ( data: Buffer ) => {
					const dataStr = data.toString()
					
					if ( /^GET \/pac/.test ( dataStr )) {
						logger(colors.blue(dataStr))
						const httpHead = new HttpProxyHeader ( data )
						agent = httpHead.headers['user-agent']
						const sock5 = /Firefox|Windows NT|WinHttp-Autoproxy-Service|Darwin/i.test ( agent ) && ! /CFNetwork|WOW64/i.test ( agent )
						
						
						const ret = getPac ( httpHead.host, this.proxyPort, /pacHttp/.test( dataStr ), sock5 )
						console.log ( `/GET \/pac from :[${ socket.remoteAddress }] sock5 [${ sock5 }] agent [${ agent }] httpHead.headers [${ Object.keys( httpHead.headers )}]`)
						console.log ( dataStr )
						console.log ( ret )
						return socket.end ( ret )
					}
					
					switch ( data.readUInt8 ( 0 )) {

						case 0x4: {
							return socks = new Socks.sockt4 ( socket, data, agent, this )
						}
							
						case 0x5: {
							return socks = new Socks.socks5 ( socket, data, agent, this )
						}
							
						default: {
							return httpProxy ( socket, data, this.gateway, this.debug )
						}
					}
				})

				socket.on ( 'error', err => {
					socks = null
				})

				socket.once ( 'end', () => {
					this.clientSockets.delete(socket)
					socks = null
				})
				
			})

			this.server.on ( 'error', err => {
				logger ( colors.red(`proxy server : ${ err.message }` ))
				
			})

			this.server.maxConnections = 65536

			this.server.listen ( proxyPort, () => {
				return logger ( colors.blue(`proxy start success on port : [${ proxyPort }]`))
			})

		}

	public exit () {
		logger ( colors.red(`************ proxyServer on exit ()`))
		this.gateway = null
	}

	public close ( Callback ) {
		return this.server.close( err => {
			this.clientSockets.forEach ( n => {
				if ( typeof n.end === 'function') {
					n.end()
				}
			})
			
			return Callback()
		})
		
	}

}

