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

import type { Socket, Server } from 'net'
import { isIPv4, connect, createServer } from 'net'
import { lookup } from 'dns'
import { Writable  } from 'stream'
import * as Compress from './compress'
import { writeFile } from 'fs'
import { logger, hexDebug } from './log'
import colors from 'colors/safe'
import { request } from 'https'
const MaxAllowedTimeOut = 1000 * 60 * 60
const blockHostFIleName = './blockHost.json'

const otherRespon = ( body: string| Buffer, _status: number ) => {
	const Ranges = ( _status === 200 ) ? 'Accept-Ranges: bytes\r\n' : ''
	const Content = ( _status === 200 ) ? `Content-Type: text/html; charset=utf-8\r\n` : 'Content-Type: text/html\r\n'
	const headers = `Server: nginx/1.6.2\r\n`
					+ `Date: ${ new Date ().toUTCString()}\r\n`
					+ Content
					+ `Content-Length: ${ body.length }\r\n`
					+ `Connection: keep-alive\r\n`
					+ `Vary: Accept-Encoding\r\n`
					//+ `Transfer-Encoding: chunked\r\n`
					+ '\r\n'

	const status = _status === 200 ? 'HTTP/1.1 200 OK\r\n' : 'HTTP/1.1 404 Not Found\r\n'
	return status + headers + body
}

const return404 = () => {
	const kkk = '<html>\r\n<head><title>404 Not Found</title></head>\r\n<body bgcolor="white">\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx/1.6.2</center>\r\n</body>\r\n</html>\r\n'
	return otherRespon ( Buffer.from ( kkk ), 404 )
}

const jsonResponse = ( body: string ) => {
	const headers = `Server: nginx/1.6.2\r\n`
		+ `Date: ${ new Date ().toUTCString()}\r\n`
		+ `Content-Type: application/json; charset=utf-8\r\n`
		+ `Content-Length: ${ body.length }\r\n`
		+ `Connection: keep-alive\r\n`
		+ `Vary: Accept-Encoding\r\n`
		//+ `Transfer-Encoding: chunked\r\n`
		+ '\r\n'
	const status = 'HTTP/1.1 200 OK\r\n'
	return status + headers + body
}

const returnHome = () => {
	const kkk = 
`<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
`
return otherRespon ( kkk, 200 )
}

const dnsLookup = ( hostName: string, CallBack ) => {
	console.log ( `on dnsLookup: hostName = [${ hostName }]` )
	return lookup ( hostName, { all: true }, ( err, data ) => {
		if ( err )
			return CallBack ( err )
		const _buf = Buffer.from ( JSON.stringify ( data ))
		return CallBack ( null, _buf )
	})
}

interface blockList {
	host: string
	port: string
	date: string
	error: string
}

const saveConnectErrorIPAddress = ( blockedHost: blockList[], CallBack ) => {
	return writeFile ( blockHostFIleName, JSON.stringify (blockedHost), 'utf8', CallBack )
}


class FirstConnect extends Writable {
	private socket: Socket = null
	constructor ( private debug: boolean, private clientSocket: Socket, private encrypt: Compress.encryptStream, private decrypt: Compress.decryptStream, private freeDomain: string[], private freeIpaddress: string[], private blockList: blockList[], 
		private hostCount: Map < string, number >) { super ()}
    
	public _write ( chunk: Buffer, encode, cb ) {

		//		first time
		// if ( !chunk?.length ) {
		// 	return cb (new Error (`chunk EOF!`))
		// }
		const _data = chunk.toString ()
		let data: VE_IPptpStream = null
		try {
			data = JSON.parse ( _data )
		} catch ( e ) {
			console.log ( `FirstConnect JSON.parse [${ _data }]catch error:` , e )
			return cb ( e )
		}


		
		if ( ! this.socket ) {
			
			let _isIpv4 = false
			/**
			 * 				Client Doname Dnslook test 
			 */
			if ( data.hostName?.length ) {
				//console.log ( `data.host [${ data.host }] is free `)
				return dnsLookup ( data.hostName, ( err, data ) => {
					if ( err ) {
						return cb ( err )
					}

					this.encrypt.pipe ( this.clientSocket )
					this.encrypt.end ( data )
				})
			}
			
			
			if ( data.uuid ) {
				_isIpv4 = isIPv4 ( data.host )
				this.encrypt.id = this.decrypt.id = 
					`{ ${ colors.grey( data.uuid )} } ${ colors.green ( this.decrypt.id ) }[${_isIpv4?colors.green('IPv4'):colors.red('IPv6')}] ---ssl[${ colors.green( data.ssl ? 'true': 'false' ) }]--->[ ${ colors.green( data.host + ':' + data.port) } ]`

				const hostMatch = data.host + ':' + data.port

				let hostCount = this.hostCount.get ( hostMatch ) || 0
				this.hostCount.set ( hostMatch, ++ hostCount )
				const isBlacked = this.blockList.findIndex ( n => n.host === data.host ) > -1 ? true : false
				
				if ( isBlacked ) {
					logger (colors.red(`*************************** [${ this.decrypt.id }] in blockList STOP it!`))
					return cb ( new Error ( `[${ data.host }] in blockList` ))
				}

				this.socket = connect ( data.port, data.host, () => {

					this.socket.pipe ( this.encrypt ).pipe ( this.clientSocket ).pipe( this.decrypt ).pipe( this.socket )

					const buffer = Buffer.from ( data.buffer, 'base64' )
					if (this.debug ) {
						logger(colors.blue(`write buffer to Target ${ this.decrypt.id } `))
						hexDebug(buffer)
					}
					
					this.socket.write ( buffer )
					return cb ()
				})

				this.socket.once ( 'end', () => {
					logger( colors.blue(`${ this.decrypt.id } Target on END()`))
					return this.clientSocket.destroy()
				})

				this.socket.once ( 'error', err => {
					logger ( colors.red(`FirstConnect ${ this.decrypt.id } Target socket on error! [${ err.message }]`))
					//this.blockList.push ({ host: data.host, port: data.port, error: err.message, date: new Date().toISOString ()})
					this.clientSocket.destroy()
					this.end ()
					
					// return saveConnectErrorIPAddress ( this.blockList, err => {
					// 	if ( err ) {
					// 		console.log ( `saveConnectErrorIPAddress error`, err )
					// 	}
					// })
				})

				return
			}

			console.log (`data.uuid == null!`)
			return cb ( new Error ( 'unknow connect!' ))
			
		}

		//		the next stream
		if (this.debug ) {
			logger (colors.blue(`FirstConnect next chunk coming:`))
			hexDebug (chunk)
		}


		if ( this.socket.writable ) {
			return this.socket.write ( Buffer.from ( chunk.toString(), 'base64' ), err => {
				if ( err ) {
					this.socket.once ('drain', () => {
						return cb ()
					})
				}
				return cb ()
			})
			
		}
		
		return cb ( new Error ( 'FirstConnect socket.writable=false' ))
	}
}

const IsBase64 = ( base64String: string ) => {
	// Credit: oybek https://stackoverflow.com/users/794764/oybek
	if ( /^[a-zA-Z0-9\+/]*={0,2}$/.test(base64String)) {
		return true
	}
	return false
}


class preProcessData {
	private id = `[${ colors.green( this.socket.remoteAddress ) + colors.red(':') + colors.green( this.socket.remotePort.toString())}]`
	private buffer = ''
	private _freeDomain: string [] = []
	private _freeIpAddress: string [] = []
	private blockList: blockList[] = []
	private hostConet = new Map ()
	
	private closeWith404 () {
		this.debug ? hexDebug (Buffer.from(this.buffer)) : null
		logger(colors.red(`${this.id} used unknow command close connecting`))
		this.socket.end (return404())
		return this.socket.destroy ()
	}

	private closeWithHome () {
		logger(colors.red(`${this.id} access home`))
		this.socket.end (returnHome())
		return this.socket.destroy ()
	}

	private firstConnectV2 = (cmd: string) => {
		if (this.debug ) {
			logger(colors.red(`new Connect from ${ this.socket.remoteAddress}:${ this.socket.remotePort }`))
		}
		const streamDecrypt = new Compress.decryptStream ( this.id, this.debug, this.password, () => {
			return
		})

		streamDecrypt.once ( 'error', err => {
			logger (colors.red(`${this.id} streamDecrypt had error STOP connecting err: ${ err.message }`))
			return this.closeWith404 ()
		})
		

		const streamEncrypt = new Compress.encryptStream ( this.socket, this.id, this.debug, this.password, Math.random()*500, () => {
			return 
		}, null, err => {
			
			const firstConnect = new FirstConnect ( this.debug, this.socket, streamEncrypt, streamDecrypt, this._freeDomain, this._freeIpAddress, this.blockList, this.hostConet )

			firstConnect.once ( 'error', err => {
				logger ( colors.red(`${ this.id } FirstConnect class on Error: ${ err.message }`))
				return this.closeWith404 ()
			})

			streamDecrypt.once('data', data => {
				firstConnect.write (data)
			})
			
			return streamDecrypt.write ( cmd + '\r\n\r\n' )
		})

		streamEncrypt.once ('error', err => {
			logger(colors.red(`${ this.id } streamEncrypt on error! STOP socket`))
			if ( this.socket && typeof this.socket.destroy === 'function') {
				this.socket.destroy ()
			}
		})

	}

	constructor(private socket: Socket, private password: string, private debug: boolean){

		socket.once ('data', data => {
			this.buffer += data.toString()

			if (!/\r\n\r\n/.test (this.buffer)) {
				return
			}

			const block = this.buffer.split('\r\n\r\n')
			const headers = block[0].split ('\r\n')
			const command = headers[0].split(' ')

			if (!/^GET$|^POST$/.test (command[0])) {
				logger(colors.red(`${ this.id } got know command 【${ command[0] }】STOP connection!`))
				return this.closeWith404()
			}

			if ( /^\/$/.test(command[1])) {
				
				return this.closeWithHome ()
			}

			if ( /^POST$/.test(command[0]) && command[1] ===`/${ password }`) {
				this.socket.end (jsonResponse (JSON.stringify({passwd:password})))
				return  this.socket.destroy()
			}

			if (command[1].length < 80 ) {
				return this.closeWith404()
			}
			
			return this.firstConnectV2(command[1].substr(1))

		})
	}
}

export class ssModeV3 {
	private tq_running = false
	private blockList = []
	private printConnects () {
		return this.serverNet.getConnections((err, count)=> {
			return logger (colors.blue (`Connections [${ count }]`))
		})
	}
	private serverNet: Server = null
	private makeNewServer (){

		this.serverNet = createServer ( socket => {
			this.printConnects ()
			return new preProcessData( socket,this.password, this.debug )
		})

		this.serverNet.listen ( this.port, null, 16384, () => {
			return logger (colors.blue(`\n**************************************************\nGateway server start listen at port [${ this.port }] password[${ this.password }] DEBUG [${ this.debug }]\n**************************************************`))
		})

		this.serverNet.once ('error', err => {
			logger (colors.red (`Gateway server once ERROR, restart now, [${ err.message }]`))
			this.serverNet.removeAllListeners ()
			this.serverNet.close (() => {
				return this.makeNewServer ()
			})
			
		})
	}

	private tq_request () {

		if (this.tq_running) {
			return logger(`tq_request already running!`)
		}
		this.tq_running = true
		const repert = () => {
			if (!this.tq_running) {
				return logger (`tq_request repert setTimeout already running!`)
			}
			this.tq_running = false

			setTimeout (() => {
				this.tq_request ()
			}, 1000 * 60 * 5)
		}
		const options = {
			hostname: 'tq-proxy.13b995b1f.ca',
			port: 443,
			path: '/',
			method: 'POST'
		}

		const req = request(options, (res) => {
			let data = ''

			res.on ('data', d => {
				data += d
			})
			res.once ('end', () => {
				logger (`tq_request success!`)
				return repert()
			})
		})

		req.once('error', (e) => {
			logger(`tq_request request on error`, e.message )
			return repert()
		})

		return req.end()
	}

	constructor ( private port: number, private password, public debug: boolean = false, tq: boolean ) {
		this.makeNewServer ()
		if ( tq) {
			this.tq_request ()
		}
		try {
			this.blockList = require (blockHostFIleName)
		} catch ( ex ) {
			this.blockList = [
				{host: '42.63.21.217', error: 'connect ETIMEDOUT', port: '443', date: new Date ().toISOString()},
				{host: '139.170.156.220', error: 'connect ETIMEDOUT', port: '443', date: new Date ().toISOString()}
			]
		}
	}
}