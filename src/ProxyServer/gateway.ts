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

import * as Compress from './compressClient'
import * as Net from 'net'
import * as res from './res'
import * as Stream from 'stream'
import * as Crypto from 'crypto'
import { logger, hexDebug } from '../GateWay/log'
import colors from 'colors/safe'
import { inspect } from 'util'

const Day = 1000 * 60 * 60 * 24

const otherRequestForNet = ( path: string, host: string, port: number, UserAgent: string ) => {
	if ( path.length < 1024 + Math.round( Math.random () * 4000 )) 
		return `GET /${ path } HTTP/1.1\r\n` +
				`Host: ${ host }${ port !== 80 ? ':'+ port : '' }\r\n` +
				`Accept: */*\r\n` +
				`Accept-Language: en-ca\r\n` +
				`Connection: keep-alive\r\n` +
				`Accept-Encoding: gzip, deflate\r\n` +
				`User-Agent: ${ UserAgent ? UserAgent : 'Mozilla/5.0' }\r\n\r\n`
	return 	`POST /${ Crypto.randomBytes ( 10 + Math.round ( Math.random () * 1500 )).toString ( 'base64')} HTTP/1.1\r\n` +
			`Host: ${ host }${ port !== 80 ? ':'+ port : '' }\r\n` +
			`User-Agent: ${ UserAgent ? UserAgent : 'Mozilla/5.0' }\r\n\r\n` +
			`Content-Length: ${ path.length }\r\n\r\n` +
			path + '\r\n\r\n'
}

class hostLookupResponse extends Stream.Writable {
	constructor ( private CallBack: ( err?: Error, dns?: domainData ) => void ) { super ()}
	public _write ( chunk: Buffer, enc, next ) {
		//console.log ( `hostLookupResponse _write come [${ chunk.toString()}]`)
		const ns = chunk.toString ( 'utf8' )
		try {
			const _ret = JSON.parse ( ns )
			const ret: domainData = {
				expire: new Date().getTime () + Day,
				dns: _ret
			}
			this.CallBack ( null, ret )
			next ()
			return this.end ()
		} catch ( e ) {
			return next ( e )
		}
	}
}

export default class gateWay {
	
	private userAgent = null
	private currentGatewayPoint = 0
	private currentgateway: multipleGateway
	public RemoteServerDistroyed = false 
	
	
	private request ( str: string, gateway: IConnectCommand ) {
		return Buffer.from ( otherRequestForNet ( str, gateway.gateWayIpAddress, gateway.gateWayPort, this.userAgent ))
	}

	private getCurrentGateway () {
		if ( this.multipleGateway.length === 1 ) {
			return this.multipleGateway [0]
		}
		if ( ++ this.currentGatewayPoint > this.multipleGateway.length - 1 ) {
			this.currentGatewayPoint = 0
		}
		return this.multipleGateway [ this.currentGatewayPoint ]
	}

	constructor ( private multipleGateway: IConnectCommand[], private debug) {
	}

	public hostLookup ( hostName: string, userAgent: string, CallBack: ( err?: Error, hostIp?: domainData ) => void ) {


		const _data = Buffer.from ( JSON.stringify ({ hostName: hostName }))
		const gateway = this.getCurrentGateway ()
		const id = colors.blue(`hostLookup`)
		const encrypt = new Compress.encryptStream ( id, gateway.randomPassword, 3000, ( str: string ) => {
			return this.request ( str, gateway )
		}, this.debug )
		
		const finish = new hostLookupResponse ( CallBack )
		
		const httpBlock = new Compress.getDecryptClientStreamHttp ( this.debug, id )
		const decrypt = new Compress.decryptStream ( gateway.randomPassword, id, this.debug )
		
		logger (`try connect gateway server: [${ gateway.gateWayIpAddress }:${ gateway.gateWayPort }] password[${ gateway.randomPassword }]`)

		const _socket = Net.createConnection ( gateway.gateWayPort, gateway.gateWayIpAddress, () => {
			logger (`connected Gateway [${ gateway.gateWayIpAddress }: ${ gateway.gateWayPort }] doing encrypt.write ( _data )`)
			encrypt.write ( _data )
		})

		_socket.once ( 'end', () => {

			//console.log ( `_socket.once end!` )
		})

		_socket.once ('error', err => {
			return CallBack ( err )
		})

		httpBlock.once ( 'error', err => {
			logger (`hostLookup httpBlock.on error`, err )
			_socket.end ( res._HTTP_502 )
			return CallBack ( err )
		})

		decrypt.once ( 'err', err => {
			CallBack ( err )
		})

		encrypt.pipe ( _socket ).pipe ( httpBlock ).pipe ( decrypt ).pipe ( finish )

	}

	public requestGetWay ( requestObj: requestObj, uuuu: VE_IPptpStream, userAgent: string, socket: Net.Socket ) {
		
		//			remote server was stoped
		if ( this.RemoteServerDistroyed ) {
			console.log (`requestGetWay this.RemoteServerDistroyed === true !`)
			return socket.end ( res._HTTP_404 )
		}
		this.userAgent = userAgent
		const gateway = this.getCurrentGateway ()

		//		remote gateway error
		if ( !gateway ) {
			return socket.end ( res._HTTP_404 )
		}

		let id = colors.yellow(`[${uuuu.uuid}]${uuuu.host}:${uuuu.port}->[Gateway ${gateway.gateWayIpAddress}:${gateway.gateWayPort}]`)
		
		const decrypt = new Compress.decryptStream ( gateway.randomPassword, id, this.debug )
		const encrypt = new Compress.encryptStream ( id, gateway.randomPassword, Math.random()*500, ( str: string ) => {
			return this.request ( str, gateway )
		}, this.debug )

		const httpBlock = new Compress.getDecryptClientStreamHttp ( this.debug, id )

		httpBlock.once ( 'error', err => {
			socket.end ( res._HTTP_404 )
		})

		decrypt.once ('error', err => {
			logger(colors.red(`requestGetWay decrypt [${ id }] on error [${ err.message }]`))
			socket.end ( res._HTTP_404 )
		})

		encrypt.once ( 'end', () =>{
			//console.log (`encrypt.once end` )
			socket.end ( res._HTTP_404 )
		})

		encrypt.once ( 'error', err => {
			console.log (`requestGetWay [${ id }] encrypt.once error`, err )
			socket.end ( res._HTTP_404 )
		})

		if (this.debug ) {
			logger(colors.red(`requestGetWay to [${gateway.gateWayIpAddress}:${ gateway.gateWayPort }] for [${ inspect( requestObj, false, 3, true ) }]`))
			hexDebug(Buffer.from(uuuu.buffer, 'base64'))
		}

		const connect = () => {
			if ( !encrypt.writable ) {
				return setTimeout(() => {
					logger(`!encrypt.writable waiting 200ms`, inspect(requestObj, false, 3, true))
					return connect()
				}, 200)
			}
			const _socket = Net.createConnection ( gateway.gateWayPort || 80, gateway.gateWayIpAddress, () => {
				id = colors.blue(`[${ _socket.localAddress }:${ _socket.localPort }] `) + id 
				if ( encrypt && encrypt.writable ) {
					if (this.debug ) {
						logger( colors.red(`${ id } success to Gateway! send data now.`))
						hexDebug(Buffer.from (uuuu.buffer, 'base64'))
					}
					return encrypt.write ( Buffer.from ( JSON.stringify ( uuuu ), 'utf8' ), () => {
						socket.resume()
					})
					
				}
				
				logger( colors.red(`encryptStream writable false!`), inspect(requestObj, false, 3, true))
				return socket.end ( res._HTTP_404 )
				
			})


			_socket.once ( 'error', err => {
				logger ( colors.red(`Gateway server [${ gateway.gateWayIpAddress }] on error ${ colors.grey( err.message )}`))
				socket.end ( res._HTTP_404 )
			})

			_socket.once ('end', () => {
				logger(colors.blue(`Gateway ${uuuu.uuid } on end()`))
				socket.destroy ()
			})

			socket.pipe ( encrypt ).pipe ( _socket ).pipe ( httpBlock ).pipe ( decrypt ).pipe ( socket )
		}
		
		return connect()
		
		
	}
}