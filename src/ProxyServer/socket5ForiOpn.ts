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
import * as Rfc1928 from './rfc1928'
import * as res from './res'
import * as Crypto from 'crypto'
import { checkDomainInBlackList, isAllBlackedByFireWall } from './client'
import httpProxyHeader from './httpProxy'
import type { proxyServer } from './client'
import * as Util from 'util'
import { logger, hexDebug } from '../GateWay/log'
import colors from 'colors/safe'
import { Socket } from 'dgram'


//	socks 5 headers

const server_res = {
	NO_AUTHENTICATION_REQUIRED: Buffer.from ('0500', 'hex')
}

const isSslFromBuffer = ( buffer: Buffer ) => {
	const ret = buffer[0] === 0x16 && buffer[1] === 0x03
	return ret
}

const getHostNameFromSslConnection = ( buffer: Buffer ) => {
	
	if (!isSslFromBuffer(buffer)) {
		return null
	}
	const lengthPoint = buffer.readInt16BE(0x95)
	const serverName = buffer.slice (0x97, 0x97 +lengthPoint)
	//	00000090  00 02 01 00 00 0A 00 08 00 06 00 1D 00 17 00 18  ................
	//	use IP address
	if (lengthPoint === 0x0A00 && serverName[0] === 0x8 && serverName[1] === 0x0) {
		return null
	}
	hexDebug(serverName)
	logger(`getHostNameFromSslConnection lengthPoint[${lengthPoint.toString(16)}] === 0x0A ${lengthPoint === 0x0A00} serverName[0] [${serverName[0].toString(16)}] serverName[0] === 0x8 ${serverName[0] === 0x8} && serverName[1] [${serverName[1].toString(16)}]  === 0x06 [${serverName[1] === 0x0}] `)
	return serverName.toString()
}

export class socks5 {
	private host: string = null
	public ATYP: number = null
	public port: number = null
	public cmd: number = null
	private _cmd = ''
	public targetIpV4: string = null
	private keep = false
	private clientIP: string = this.socket.remoteAddress.split(':')[3] || this.socket.remoteAddress
	private debug = this.proxyServer.debug
	private uuid = Crypto.randomBytes (10).toString ('hex')

	private stopConnection (req: Rfc1928.Requests) {
		req.REP = Rfc1928.Replies.COMMAND_NOT_SUPPORTED_or_PROTOCOL_ERROR
		return this.socket.write ( req.buffer )
	}
	private closeSocks5 ( buffer: Buffer ) {
		//console.log (`close proxy socket!`)
		if ( this.socket ) {
			if ( this.socket.writable ) {
				this.socket.end ( buffer )
			}

			if ( typeof this.socket.removeAllListeners === 'function' )
				this.socket.removeAllListeners()
		}
	}

	private connectStat3 ( req: Rfc1928.Requests ) {
		let userAgent = ''
		switch (req.cmd) {
			case Rfc1928.CMD.CONNECT: {
				break
			}
			case Rfc1928.CMD.BIND: {
			}
			case Rfc1928.CMD.UDP_ASSOCIATE: {
			}
			default: {
				return this.stopConnection(req)
			}
		}
		const uuuu : VE_IPptpStream = {
			uuid: this.uuid,
			host: req.host,
			hostIPAddress: req.hostAddress,
			buffer: '',
			cmd: this._cmd,
			port: req.port,
			ssl: false
		}
		const requestObj: requestObj = {
			remotePort:　this.socket.remotePort,
			remoteAddress: this.socket.remoteAddress,
			targetHost: uuuu.host,
			targetPort: uuuu.port,
			methods: '',
			socks: 'Sock5',
			uuid: uuuu.uuid
		}

		this.socket.once ( 'data', ( _data: Buffer ) => {

			//			gateway shutdown
			if ( !this.proxyServer.gateway ) {
				//console.log (`SOCK5 !this.proxyServer.gateway STOP sokcet! res.HTTP_403`)
				return this.socket.end ( res._HTTP_PROXY_302() )
			}
			if ( this.debug ) {
				logger(`connectStat3 buffer`)
				hexDebug(_data)
			}
			uuuu.ssl = isSslFromBuffer (_data)

			if (!uuuu.ssl) {
				const httpHeader = new httpProxyHeader (_data)
				uuuu.host = httpHeader.host
				userAgent = httpHeader.headers [ 'user-agent' ]
				requestObj.methods = httpHeader.methods
			}

			uuuu.buffer = _data.toString ( 'base64' )
			if ( this.debug ) {
				logger(Util.inspect(uuuu))
				logger(Util.inspect(requestObj))
			}
			return this.proxyServer.gateway.requestGetWay ( requestObj, uuuu, userAgent, this.socket )
		})
		req.REP = Rfc1928.Replies.GRANTED
		return this.socket.write ( req.buffer )
	}
	
	private udpProcess ( data: Rfc1928.Requests ) {
		data.REP = Rfc1928.Replies.GRANTED
		return this.socket.write ( data.buffer )
	}
	
	private connectStat2 ( data: Buffer ) {

		if ( this.debug ) {
			hexDebug(data)
		}
		const req = new Rfc1928.Requests ( data )

		this.ATYP = req.ATYP
		this.host = req.domainName
		this.port = req.port
		this.cmd = req.cmd
		this.targetIpV4 = req.ATYP_IP4Address

		//.serverIP = this.socket.localAddress.split (':')[3]

		//		IPv6 not support!
		
		switch ( this.cmd ) {

			case Rfc1928.CMD.CONNECT: {
				
				this.keep = true
				this._cmd = 'CONNECT'
				break
			}
			case Rfc1928.CMD.BIND: {
				this._cmd = 'BIND'
				break
			}
			case Rfc1928.CMD.UDP_ASSOCIATE: {
				this._cmd = 'UDP_ASSOCIATE'
				//logger( `Rfc1928.CMD.UDP_ASSOCIATE data[${ data.toString ('hex')}]` )
				break
			}
			default: {
				this._cmd = 'UNKNOW'
				logger (`Socks 5 unknow cmd: `, data.toString('hex'), Util.inspect(req, false, 3, true))
				break
			}
				
		}

		//			IPv6 not support 
		// if ( req.IPv6 ) {
		// 	this.keep = false
		// }
		const obj = { ATYP:this.ATYP, host: this.host, hostType: typeof  this.host, port: this.port, targetIpV4: this.targetIpV4 , cmd: this._cmd, buffer: data.toString('hex') }
		if ( ! this.keep ) {
			req.REP = Rfc1928.Replies.COMMAND_NOT_SUPPORTED_or_PROTOCOL_ERROR
			if ( this.debug ) {
				logger(colors.red(`Rfc1928.Replies.COMMAND_NOT_SUPPORTED_or_PROTOCOL_ERROR STOP socks 5 connecting.`))
				logger(Util.inspect(obj))
			}
			return this.closeSocks5 ( req.buffer )
		}
		if ( this.cmd === Rfc1928.CMD.UDP_ASSOCIATE ) {
			return logger ('this.cmd === Rfc1928.CMD.UDP_ASSOCIATE skip!')
		}
		return this.connectStat3 (req)
	}

	constructor ( private socket: Net.Socket, private data: Buffer, private agent: string, private proxyServer: proxyServer ) {
		if ( this.debug ) {
			logger (colors.yellow(`new socks v5`))
			hexDebug(data)
		}
		this.socket.once ( 'data', ( chunk: Buffer ) => {
			return this.connectStat2 ( chunk )
		})
		this.socket.write ( server_res.NO_AUTHENTICATION_REQUIRED )
		this.socket.resume ()
	}
}

export class sockt4 {
	private req = new Rfc1928.socket4Requests ( this.buffer )
	private host = this.req.domainName
	private port = this.req.port
	private uuid = Crypto.randomBytes (10).toString ('hex')
	private cmd = this.req.cmd
	private _cmd = ''
	private targetIpV4 = this.req.targetIp
	private keep = false
	private debug = false
	private id = colors.blue(`[${ this.uuid}] [${ this.socket.remoteAddress}:${this.socket.remotePort}] --> [${ this.host}:${ this.port}]`)
	constructor ( private socket: Net.Socket, private buffer: Buffer, private agent: string, private proxyServer: proxyServer ) {
		this.debug = proxyServer.debug
		this.socket.pause ()

		if ( this.debug ) {
			logger (colors.yellow(`new socks v4`))
			hexDebug(buffer)
		}
		
		switch ( this.cmd ) {
			case Rfc1928.CMD.CONNECT: {
				this.keep = true
				this._cmd = 'CONNECT'
				if ( this.debug ) {
					logger(colors.gray(`${ this.id} sockt4 got Rfc1928 command ${colors.magenta('CONNECT')}`))
				}
				break
			}
			case Rfc1928.CMD.BIND: {
				
				this._cmd = 'BIND'
				if ( this.debug ) {
					logger(colors.gray(`${ this.id} sockt4 got Rfc1928 command ${colors.magenta('BIND')}`))
				}
				break
			}
			case Rfc1928.CMD.UDP_ASSOCIATE: {
				if ( this.debug ) {
					logger(colors.gray(`${ this.id} sockt4 got Rfc1928 command ${colors.magenta('UDP_ASSOCIATE')}`))
				}
				this._cmd = 'UDP_ASSOCIATE'
				break
			}
			default: {
				logger(colors.red(`${ this.id } sockt4 got Rfc1928 unknow command [${ this.cmd }]`))
				
				this._cmd = 'UNKNOW'
				break
			}
				
		}
		if ( ! this.keep ) {
			this.debug ? logger (colors.red(`STOP session`)): null
			this.socket.end ( this.req.request_failed )
			return
		}

		this.connectStat2 ()

	}
	public connectStat2 () {

		this.socket.once ( 'data', ( _data: Buffer ) => {
			if ( this.debug ) {
				logger (`SOCK4 connectStat2 [${ this.host || this.targetIpV4 }] get data`)
				hexDebug(_data)
			}
			

			if ( !this.proxyServer.gateway ) {
				logger ( colors.red(`SOCK4 !this.proxyServer.gateway STOP sokcet! res.HTTP_403`))
				return this.socket.end ( res._HTTP_PROXY_302 () )
			}

			this.connect (_data)

		})
		const buffer = this.req.request_4_granted ( '0.0.0.255', this.port )
		this.socket.write ( buffer )
		return this.socket.resume ()
	}

	public connect ( buffer: Buffer) {
		
		const isSsl = isSslFromBuffer ( buffer )
		let userAgent = ''
		let methods = 'GET'
		let httpHeader: httpProxyHeader = null
		const uuuu : VE_IPptpStream = {
			uuid: this.uuid,
			host: this.host,
			hostIPAddress: this.req.targetIp,
			buffer: buffer.toString ( 'base64' ),
			cmd: this._cmd,
			port: this.req.port,
			ssl: isSslFromBuffer ( buffer )
		}
		
		if (!isSsl) {
			httpHeader = new httpProxyHeader (buffer)
			uuuu.host = httpHeader.host
			userAgent = httpHeader.headers [ 'user-agent' ]
			methods = httpHeader.methods
		}
		
		const requestObj: requestObj = {
			remotePort:　this.socket.remotePort,
			remoteAddress: this.socket.remoteAddress,
			targetHost: uuuu.host,
			targetPort: uuuu.port,
			methods: httpHeader ? httpHeader.methods : 'CONNECT',
			socks: this.req.targetIp ? 'Sock4' : 'Sock4a',
			uuid: uuuu.uuid
		}

		if ( this.debug ) {
			logger(Util.inspect (uuuu, false, 3, true ))
			logger(Util.inspect (requestObj, false, 3, true ))
		}

		if ( this.proxyServer.gateway && typeof this.proxyServer.gateway.requestGetWay === 'function' ) {
			
			return this.proxyServer.gateway.requestGetWay ( requestObj, uuuu, userAgent, this.socket )
		}

		return 　this.socket.end ( this.req.request_failed )
	}
}


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