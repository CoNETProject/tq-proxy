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

import * as crypto from 'crypto'
import * as Async from 'async'
import * as Stream from 'stream'
import { writeFile, createReadStream } from 'fs'
import { exec } from 'child_process'
import * as Uuid from 'node-uuid'
import colors from 'colors/safe'
import { hexDebug, logger } from './log'
import type { Socket } from 'net'

const EOF = Buffer.from ( '\r\n\r\n', 'utf8' )

export interface packetBuffer {
	command: number;
	uuid: string;
	buffer: Buffer;
	serial: number
}

export interface pairConnect {
	serverListen: string;
	clientListen: string;
}

const HTTP_HEADER =
	Buffer.from (`HTTP/1.1 200 OK\r\nDate: ${ new Date ().toUTCString ()}\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nVary: Accept-Encoding\r\n\r\n`)

export class encryptStream extends Stream.Transform {
	private salt: Buffer
	private iv: Buffer
	public ERR: Error = null
	private first = 0
	public derivedKey: Buffer = null
	public dataCount = false

	private initCrypt (CallBack) {
		return Async.waterfall ([
			next => crypto.randomBytes ( 64, next ),
			( _salt, next ) => {
				this.salt = _salt
				crypto.randomBytes ( 12, next )
			},
			( _iv, next ) => {
				this.iv = _iv
				try {
					crypto.pbkdf2 ( this.password, this.salt, 2145, 32, 'sha512', next)
				} catch (ex) {
					return next (ex)
				}
				
			}
		], ( err, derivedKey ) => {
			if ( err ) {
				console.log (colors.red(`encryptStream init error ${ err.message } TRY again`))
				return this.initCrypt (CallBack)
			}
				
			this.derivedKey = derivedKey
			return CallBack ()
		})
	}
	constructor ( private socket: Socket, public id: string, private debug: boolean, private password: string, private random: number, public download:( n: number ) => void, private httpHeader : ( str: string ) => Buffer, CallBack ) {
		super ()
		this.initCrypt (CallBack)
	}
	
	public _transform ( chunk: Buffer, encode, cb ) {

		this.first ++
		if ( this.debug ) {
			logger( colors.blue(`${ this.id } encryptStream got Buffer from Target【${ colors.red( this.first.toString()) }】`))
			hexDebug(chunk)
		}
		
		if ( this.first < 5 ) {
			const cipher = crypto.createCipheriv ( 'aes-256-gcm', this.derivedKey, this.iv )

			let _text = Buffer.concat ([ Buffer.alloc ( 4, 0 ) , chunk ])
	
			_text.writeUInt32BE ( chunk.length, 0 )
	
			if ( chunk.length < this.random ) {
				_text = Buffer.concat ([ _text, Buffer.allocUnsafe ( Math.random() * 200 )])
			}
	
			const _buf = Buffer.concat ([ cipher.update ( _text ), cipher.final ()])
			const _buf1 = Buffer.concat ([ cipher.getAuthTag (), _buf ])
	
			if ( this.dataCount ){
				//console.log ( `**** encryptStream ID[${ this.id }] dataCount is [true]! data.length`)
				this.download ( _buf1.length )
			}
				
			
			if ( this.first === 1 ) {
	
				const black = Buffer.concat ([ this.salt, this.iv, _buf1 ]).toString ( 'base64' )

				if ( ! this.httpHeader ) {
					
					const _buf4 = Buffer.from ( black, 'utf8')
					const _buffer = Buffer.concat ([ HTTP_HEADER, _buf4, EOF ])
					logger ( colors.green(`encryptStream [${ this.id }]client <--- Target _buffer = [${ _buffer.length }] 【${ colors.red( this.first.toString()) }】`))
					if ( this.debug ) {
						logger(_buffer.toString())
						hexDebug(_buffer)
					}
					
					return cb ( null, _buffer )
				}

				const _data = this.httpHeader ( black )
				logger (colors.green(`encryptStream [${ this.id }]to client client <--- Target _buffer = [${ _data.length }] 【${ colors.red( this.first.toString()) }】`))
				return cb ( null, _data )
	
			}
			if ( this.debug ) {
				logger( colors.blue(`${ this.id } [${colors.red( this.first.toString()) }] encryptStream send data`))
				hexDebug(_buf1)
			}
			
			const _buf2 = _buf1.toString ( 'base64' )
			return cb ( null, Buffer.from(_buf2+EOF) )
		}

		
		const _buf2 = Buffer.from(chunk.toString ( 'base64' ) + EOF)
		if ( this.debug ) {
			logger( colors.blue(`${ this.id } encryptStream got Buffer from Target【${ colors.red( this.first.toString()) }】Sent direct to Client`))
			hexDebug(_buf2)
		}
		if ( this.socket.writable ) {
			return cb ( null, _buf2 )
		}
		return cb(new Error(`${ this.id } encryptStream writable = false `))
	}
}

export class decryptStream extends Stream.Transform {
	private first = 0
	private salt: Buffer
	private iv: Buffer
	private derivedKey: Buffer = null
	private decipher: crypto.Decipher = null
	private text = ''

	private _decrypt ( decodeBuffer: Buffer, CallBack ) {
		return crypto.pbkdf2 ( this.password, this.salt , 2145, 32, 'sha512', ( err, derivedKey ) => {
			if ( err ) {
				logger ( colors.red(`**** decryptStream crypto.pbkdf2 ERROR: ${ err.message }` ))
				return CallBack ( err )
			}
			this.derivedKey = derivedKey

			try {
				this.decipher = crypto.createDecipheriv ( 'aes-256-gcm', this.derivedKey, this.iv )
				// @ts-ignore
				this.decipher.setAuthTag ( decodeBuffer.slice ( 0, 16 ))
			} catch ( ex ) {
				logger(colors.red(`${ this.id } 【${this.first }】 decryptStream  crypto.setAuthTag got Error ${ ex.message }`))
				hexDebug(decodeBuffer)
				return CallBack ( new Error (`${ this.id } class decryptStream firstProcess crypto.createDecipheriv Error]`) )
			}

			let _Buf = null

			try {
				_Buf = Buffer.concat ([ this.decipher.update ( decodeBuffer.slice ( 16 )) , this.decipher.final () ])
			} catch ( ex ) {
				logger(colors.red(`${ this.id } 【${this.first }】 decryptStream crypto.createDecipheriv Error ${ ex.message }`))
				hexDebug(decodeBuffer)
				return CallBack ( new Error (`class decryptStream firstProcess _decrypt error`) )
			}

			const length = _Buf.readUInt32BE (0) + 4
			const uuu = _Buf.slice ( 4, length )

			return  CallBack ( null, uuu )
			
		})
	}

	public firstProcess ( decodeBuffer: Buffer, CallBack: ( err?: Error, text?: Buffer ) => void ) {
		if ( decodeBuffer.length < 76 ) {
			return CallBack (new Error (`Unknow connect!`))
		}
		
		this.salt = decodeBuffer.slice ( 0, 64 )
		this.iv = decodeBuffer.slice ( 64, 76 )
		return this._decrypt ( decodeBuffer.slice ( 76 ), CallBack )
	}

	constructor ( public id: string, private debug: boolean, private password: string, public upload: ( n: number ) => void ) {
		super ()
	}

	public _transform ( chunk: Buffer, encode, cb ) {
		this.text += chunk.toString()
		const line = this.text.split('\r\n\r\n')

		if ( line.length < 2 ) {
			return cb ()
		}

		const callback = (err, data: Buffer ) => {
			if ( err ) {
				return cb (err)
			}
			if (this.debug ) {
				logger(`[${ this.id }] decryptStream  push data = [${ data.length }] 【${ colors.red(this.first.toString()) }】`) 
				hexDebug(data)
			}
			
			this.push (data)
			return this._transform(Buffer.from(''), encode, cb)
		}

		const firstLine = line.shift()
		
		const _chunk = Buffer.from(firstLine, 'base64')
		if ( this.debug ) {
			logger(colors.green(`${ this.id } decryptStream got DATA ${ _chunk.length }`))
			hexDebug(_chunk)
		}
		this.text = line.join('\r\n\r\n')
		this.first ++

		if ( this.first < 5 ) {
			if ( this.first === 1) {

				return this.firstProcess ( _chunk, callback )
			}
	
			return this._decrypt (_chunk, callback )
		}

		return callback (null, _chunk )
	}

	public _flush (cb) {
		
		if ( this.text.length ) {
			logger(colors.red(`${this.id } decryptStream on _flush [${this.text.length}]`))
			const _chunk = Buffer.from(this.text, 'base64')
			if (this.first < 5) {
				return this._decrypt (_chunk, (err, data) => {
					if ( err) {
						return cb (err)
					}
					this.push (_chunk)
					cb()
				})
			}
			this.push (_chunk)
		}
		
		cb()
	}
}

class encode extends Stream.Transform {
	constructor () { super ()}
	private kk = null
	public _transform ( chunk: Buffer, encode, cb ) {
		let start = chunk.slice (0)
		while ( start.length ) {
			const point = start.indexOf ( 0x0a )
			if ( point < 0 ) {
				this.push ( start )
				break
			}
			const _buf = start.slice ( 0, point )
			this.push ( _buf )
			start = start.slice ( point + 1 )
		}
		return cb ()
	}

}

class encodeHex extends Stream.Transform {
	constructor () { super ()}
	public _transform ( chunk: Buffer, encode, cb ) {
		
		return cb ( null, chunk.toString ('utf8'))
	}
}

export class getDecryptClientStreamFromHttp extends Stream.Transform {

	private first = true
	private text = ''
	constructor () { super ()}
	public getBlock ( block: string ) {
		const uu = block.split ('\r\n')
		if ( uu.length !== 2 ) {
			return null
		}
		const length = parseInt ( uu[0], 16 )
		const text = uu [1]
		if ( length === text.length ) {
			return text
		}
		console.log (`length[${length}] !== text.length [${text.length}]`)
		return null
	}

	public _transform ( chunk: Buffer, encode, cb ) {
		this.text += chunk.toString ( 'utf8' )
		const line = this.text.split ( '\r\n\r\n' )

		while ( this.first && line.length > 1 || !this.first && line.length ) {

			if ( this.first ) {
				this.first = false
				line.shift()
			}
			const _text = line.shift ()
			if ( ! _text.length )
				continue
			const text = this.getBlock ( _text )
			if ( ! text ) {
				//			middle data can't get block
				if ( line.length ) {
					console.log ( 'getDecryptStreamFromHttp have ERROR:\n*****************************\n' )
					console.log ( text )
					return this.unpipe()
				}
				this.text = _text
				return cb ()
			}
			
			this.push ( Buffer.from ( text, 'base64' ))
		}
		this.text = ''
		return cb ()
	}
}

const tenMbyte = 10240000

class saveBlockFile extends Stream.Writable {
	private length = 0
	private fileAddTag = 0
	private _chunk = Buffer.allocUnsafe(0)
	constructor ( private fileName: string, private data: fileBlokeInfo ) {
		super ()
	}
	public _write ( chunk: Buffer, encode, callback ) {
		this.length += chunk.length
		this._chunk = Buffer.concat ([ this._chunk, chunk ])
		if ( this.length < tenMbyte ) {
			return callback ()
		}
		
		const cipher = crypto.createCipheriv ( this.data.algorithm, this.data.derivedKey, this.data.iv )
		const _data = Buffer.concat ([ cipher.update ( this._chunk ), cipher.final ()])
		const fileName = this.fileName + '.' + this.fileAddTag ++
		this.data.files.push ( fileName )
		// @ts-ignore
		this.data.getAuthTag.push ( cipher.getAuthTag ().toString ( 'base64' ))
		return writeFile ( fileName, this._chunk.toString( 'base64' ), err => {
			this._chunk = Buffer.allocUnsafe(0)
			this.length = 0
			if ( err ) {
				return callback ( err )
			}
			return callback ()
		})
	}
}


export const encryptMediaFileStream = ( fileName: string, password: string, CallBack ) => {
	let enCryptoData: fileBlokeInfo = {
		salt: null,
		iv: null,
		iterations: 100000,
		keylen: 32,
		digest: 'sha512',
		derivedKey: null,
		algorithm: 'aes-256-gcm',
		files: [],
		getAuthTag: []
	}
	let cipher: crypto.Cipher = null
	Async.waterfall ([
		next => crypto.randomBytes ( 64, next ),
		( _salt, next ) => {
			enCryptoData.salt = _salt
			crypto.randomBytes ( 12, next )
		},
		( _iv, next ) => {
			enCryptoData.iv = _iv
			crypto.pbkdf2 ( password, enCryptoData.salt, enCryptoData.iterations, enCryptoData.keylen, enCryptoData.digest, next )
		}
	], ( err, derivedKey: Buffer ) => {
		if ( err )  {
			return CallBack ( err )
		}

		enCryptoData.derivedKey = derivedKey
		const readFile = createReadStream ( fileName )
		const writeFile = new saveBlockFile ( fileName, enCryptoData )
		
		readFile.once ( 'close', () => {
			console.log (`readFile.once close`)
			return CallBack ( null, enCryptoData )
		})
		readFile.pipe ( writeFile )
	})
}

const addHeaderForBase64File = ( addText: string, fileName: string, CallBack ) => {
	
	const tempFile = 'temp/' + Uuid.v4()
	const cmd = `echo -n '${ addText }' | cat - ${ fileName } > ${ tempFile } && echo -n "\r\n\r\n" >> ${ tempFile } && mv -f  ${ tempFile }  ${ fileName } `
	return exec ( cmd, CallBack )
}

export const Base64MediaFileStream3 = ( fileName: string, domainName: string, CallBack ) => {
	const text = `Content-Type: application/octet-stream\r\nContent-Disposition: attachment\r\nMessage-ID:<${ Uuid.v4() }@>${ domainName }\r\nContent-Transfer-Encoding: base64\r\nMIME-Version: 1.0\r\n\r\n`
	const cmd = `base64 ${ fileName } | split -b 10MB -d  --verbose - ${ fileName }. | sed "s/creating file '//g" | sed "s/'//g" `
	Async.series ([
		next => exec ( cmd, next ),
		next => exec ( `rm ${ fileName }`, next )
	], ( err, data: string[] ) => {

		if ( err ) {
			return CallBack ( err )
		}
		
		const files = data[0][0].split('\n')
		if ( ! files[ files.length -1 ].length ) {
			files.pop ()
		}
		
		return Async.eachSeries ( files, ( n, next ) => {
			return addHeaderForBase64File ( text, n, next )
		}, err => {
			return CallBack ( null, files )
		})
		
	})

}


