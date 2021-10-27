/*!
 * Copyright 2017 QTGate systems Inc. All Rights Reserved.
 *
 * QTGate systems Inc.
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

import { randomBytes, pbkdf2, createCipheriv, createDecipheriv, Decipher } from 'crypto'
import { waterfall } from 'async'
import { Transform, Writable } from 'stream'
import type { Socket } from 'net'
import colors from 'colors/safe'
import { hexDebug, logger } from '../GateWay/log'

const EOF = Buffer.from ( '\r\n\r\n')

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

export const encrypt = ( text: Buffer, masterkey: string, CallBack ) => {
	let salt = null
	waterfall ([
		next => randomBytes ( 64, next ),
		( _salt, next ) => {
			salt = _salt
			pbkdf2 ( masterkey, salt, 2145, 32, 'sha512', next )
		}
	], ( err, derivedKey ) => {
		if ( err )
			return CallBack ( err )
		
		randomBytes ( 12, ( err1, iv ) => {
			if ( err1 )
				return CallBack ( err1 )
			
			const cipher = createCipheriv ( 'aes-256-gcm', derivedKey, iv );
		
			let _text = Buffer.concat ([ Buffer.alloc ( 4, 0 ) , text ])
			_text.writeUInt32BE ( text.length, 0 )
			if ( text.length < 500 ) {
				 _text = Buffer.concat ([ _text, Buffer.alloc ( 100 + Math.random () * 1000 )])
			}
			const encrypted = Buffer.concat ([ cipher.update ( _text ), cipher.final ()]);
			const ret = Buffer.concat ([ salt, iv, cipher.getAuthTag(), encrypted ])
			
			return CallBack ( null, ret )
		})
	})
}
/**
 * Decrypts text by given key
 * @param String base64 encoded input data
 * @param Buffer masterkey
 * @returns String decrypted (original) text
 */
export const decrypt =  ( data: Buffer, masterkey, CallBack ) => {
	if ( !data || !data.length )
		return CallBack ( new Error( 'null' ))
	try {
		// base64 decoding

		// convert data to buffers

		const salt = data.slice ( 0, 64 );
		const iv = data.slice ( 64, 76 );
		const tag = data.slice ( 76, 92 );
		const text = data.slice ( 92 );
		// derive key using; 32 byte key length
		pbkdf2 ( masterkey, salt , 2145, 32, 'sha512', ( err, derivedKey ) => {
			
			if ( err )
				return CallBack ( err )
			// AES 256 GCM Mode
			try {
				const decipher = createDecipheriv ( 'aes-256-gcm', derivedKey, iv )
				decipher.setAuthTag ( tag )
				const decrypted = Buffer.concat([decipher.update ( text ), decipher.final ( )]) 
				const leng = decrypted.slice( 4, 4 + decrypted.readUInt32BE(0))
				return CallBack ( null, leng )
			} catch ( ex ) {
				console.log ( `decrypt catch error [${ ex.message }]`)
			}
			

			
		})

	} catch ( e ) {
		return CallBack ( e )
	}

}

export const packetBuffer = ( bit0: number, _serial: number, id: string, buffer: Buffer ) => {
	
	const _buffer = Buffer.alloc ( 6, 0 )
	_buffer.writeUInt8 ( bit0, 0 )
	_buffer.writeUInt32BE ( _serial, 1 )

	const uuid = Buffer.from ( id )
	_buffer.writeUInt8 ( id.length, 5 )
	if ( buffer && buffer.length )
		return Buffer.concat ([ _buffer, uuid, buffer ])
	return Buffer.concat ([ _buffer, uuid ])
}

export const openPacket = ( buffer: Buffer ) => {
	const idLength = buffer.readUInt8 ( 5 )
	return  {
		command: buffer.readUInt8 ( 0 ),
		serial: buffer.readUInt32BE ( 1 ),
		uuid: buffer.toString ( 'utf8', 6, 6 + idLength ),
		buffer: buffer.slice ( 6 + idLength )
	}
}
const HTTP_HEADER = Buffer.from (
	`HTTP/1.1 200 OK\r\nDate: ${ new Date ().toUTCString ()}\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nVary: Accept-Encoding\r\n\r\n`, 'utf8')
const HTTP_EOF = Buffer.from ( '\r\n\r\n', 'utf8' )

export class encryptStream extends Transform {
	private salt: Buffer
	private iv: Buffer
	private first = 0
	public derivedKey: Buffer = null

	private BlockBuffer ( _buf: Buffer ) {
		return Buffer.from( _buf.length.toString( 16 ).toUpperCase() + '\r\n', 'utf8' )
	}
	private init ( callback ) {
		return waterfall ([
			next => randomBytes ( 64, next ),
			( _salt, next ) => {
				this.salt = _salt
				randomBytes ( 12, next )
			},
			( _iv, next ) => {
				this.iv = _iv
				pbkdf2 ( this.password, this.salt, 2145, 32, 'sha512', next )
			}
		], ( err, derivedKey ) => {
			
			this.derivedKey = derivedKey
			return callback ( err )
		})
	}

	constructor ( private id: string,  private password: string, private random: number, private httpHeader : ( str: string ) => Buffer, private debug: boolean ) {
		super ()
	}
	
	public _transform ( chunk: Buffer, encode, cb ) {
		
		if ( !this.derivedKey ) {
			return this.init (() => {
				return this._transform ( chunk, encode, cb )
			})
		}


		this.first ++

		if ( this.debug ) {
			logger(`${this.id } encryptStream get DATA [${ chunk.length }] 【${ colors.red( this.first.toString() )}】`)
			hexDebug( chunk )
		}
		if ( this.first < 5 ) {
			const cipher = createCipheriv ( 'aes-256-gcm', this.derivedKey, this.iv )

			let _text = Buffer.concat ([ Buffer.alloc ( 4, 0 ) , chunk ])
	
			_text.writeUInt32BE ( chunk.length, 0 )
	
			if ( chunk.length < this.random ) {
				_text = Buffer.concat ([ _text, Buffer.allocUnsafe ( Math.random() * 1000 )])
			}
	
			const _buf = Buffer.concat ([ cipher.update ( _text ), cipher.final ()])
			const getAuthTag = cipher.getAuthTag ()
	
			const _buf1 = Buffer.concat ([ getAuthTag, _buf ])
			
			if ( this.first === 1) {
	
				const black = Buffer.concat ([ this.salt, this.iv, _buf1 ]).toString ( 'base64' )	//	 76
				if ( ! this.httpHeader ) {
					const _buf4 = Buffer.from ( black, 'base64')
					return cb ( null, Buffer.concat ([ HTTP_HEADER, this.BlockBuffer ( _buf4 ), _buf4, EOF ]))
				}
				const _buf2 = this.httpHeader ( black )
				if ( this.debug ) {
					logger(colors.blue( `${this.id} encryptStream FIRST push data---> [${ _buf2.length }]`))
					hexDebug(_buf2 )
				}
				
				return cb ( null, _buf2 )
			}
			
			const _buf2 = _buf1.toString( 'base64' )
			this.debug ? logger (colors.blue( `encryptStream [${ this.id }: step ${ colors.red( this.first.toString() )}] push data---> [${ _buf2.length }]`)): null
			return cb ( null, Buffer.from(_buf2 + EOF))
		}

		const _buffer = Buffer.from(chunk.toString('base64')+EOF)

		if ( this.debug ) {
			logger(`${this.id } encryptStream DIRECT send data to Gateway [${ _buffer.length }] 【${ colors.red( this.first.toString() )}】`)
			hexDebug( _buffer )
		}
		return cb ( null, _buffer)
	}
}

export class decryptStream extends Transform {
	private salt: Buffer
	private iv: Buffer
	private first = 0
	private derivedKey: Buffer = null
	private _decrypt ( _text: Buffer ) {
		
		const decipher = createDecipheriv ( 'aes-256-gcm', this.derivedKey, this.iv )
		decipher.setAuthTag ( _text.slice ( 0, 16 ))
		try {
			const _buf = Buffer.concat ([ decipher.update ( _text.slice ( 16 )), decipher.final () ])
			
			const leng = _buf.slice ( 4, 4 + _buf.readUInt32BE ( 0 ))
			if ( leng && leng.length ) {
				return leng
			}
			
			return Buffer.allocUnsafe ( 0 )
		} catch ( e ) {
			console.log ( 'class decryptStream _decrypt error:', e.message )
			return Buffer.allocUnsafe ( 0 )
		}
	}

	public _First ( chunk: Buffer, CallBack: ( err?: Error, text?: Buffer ) => void ) {
		this.salt = chunk.slice ( 0, 64 );
		this.iv = chunk.slice ( 64, 76 );
		return pbkdf2 ( this.password, this.salt , 2145, 32, 'sha512', ( err, derivedKey ) => {
			if ( err ) {
				console.log ( `${this.id } decryptStream crypto.pbkdf2 ERROR: ${ err.message }` )
				return CallBack ( err )
			}
			this.derivedKey = derivedKey
			const text = this._decrypt ( chunk.slice ( 76 ))
			if ( ! text.length ) {
				logger (colors.red(`decryptStream First get empty DATA send ERROR`))
				return CallBack ( new Error ( 'lenth = 0' ))
			}
			if ( this.debug ) {
				logger(colors.green(`decryptStream First <-- from gateway`))
				hexDebug (text)
			}
			
			return CallBack ( null, text )
		})
	}

	constructor ( private password: string, private id: string, private debug: boolean) {
		super ()
		debug ? logger ( colors.blue(`new decryptStream`)): null
	}

	
	public _transform ( chunk: Buffer, encode, cb ) {
		this.first ++
		if ( this.first < 5 ) {
			if ( !this.derivedKey ) {

				return this._First ( chunk, cb )
			}
			const text = this._decrypt ( chunk )
	
			if ( ! text.length ) {
				logger (colors.red(`decryptStream get empty DATA send ERROR`))
				return cb ( new Error ( 'lenth = 0'))
			}
			if ( this.debug ) {
				logger(colors.green(`decryptStream <-- from gateway 【${ colors.red(this.first.toString())}】decrypted`))
				hexDebug (text)
			}
			return cb ( null, text )
		}
		
		if ( this.debug ) {
			logger(colors.green(`decryptStream <-- from gateway 【${ colors.red(this.first.toString())}】direct`))
			hexDebug (chunk)
		}
		return cb ( null, chunk )
		
	}
}

class encode extends Transform {
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

class encodeHex extends Transform {
	constructor () { super ()}
	public _transform ( chunk: Buffer, encode, cb ) {
		
		return cb ( null, chunk.toString ('utf8'))
	}
}

export class getDecryptClientStreamHttp extends Transform {
	private first = 0
	private text = ''
	constructor ( private debug: boolean, private id: string ) { super ()}

	public _transform ( chunk: Buffer, encode, cb ) {
		
		this.text += chunk.toString ()
		const line = this.text.split ( '\r\n\r\n' )

		if ( line.length < 2 ) {
			return cb()
		}

		if (this.debug){
			logger(colors.gray(this.text))
		}
		let currentBlock = line.shift()
		this.text = line.join('\r\n\r\n')
		this.first ++
		
		if ( this.first === 1) {
			
			const headers = currentBlock.split ('\r\n')
			const command = headers[0].split(' ')
			
			if ( command[1] !== '200' ) {
				logger (colors.red(`${ this.id } !200 ERROR getDecryptClientStreamHttp <--- from Gateway`))
				return cb(new Error('Gateway return !200'))
			}

			return this._transform(Buffer.from(''), encode, cb)
		}


		const _block = Buffer.from ( currentBlock, 'base64' )
		if ( this.debug ) {
			logger (colors.blue(`${ this.id } getDecryptClientStreamHttp <--- from Gateway [${ chunk.length }] 【${colors.red( this.first.toString() )}】`))
			logger (colors.yellow(currentBlock))
		}
		this.push(_block)
		return this._transform(Buffer.from(''), encode, cb)
	}

	public _flush (cb) {
		if ( this.text.length ) {
			const _block = Buffer.from ( this.text, 'base64' )
			
			logger(colors.red(`${this.id} getDecryptClientStreamHttp on _flush`))
			if (this.debug ) {
				logger (colors.yellow(_block.toString()))
			}
			this.push(_block)
		}
		cb()
	}
}

export class printStream extends Transform {

	constructor ( private headString: string ) { super ()}
	public _transform ( chunk: Buffer, encode, cb ) {
		console.log ( this.headString )
		console.log ( chunk.toString ('hex'))
		console.log ( this.headString )
		
		return cb ( null, chunk )
	}
}

export class blockBuffer16 extends Writable {
	constructor ( private socket: Socket ) {
		super ()
		this.socket.pause ()
	}
	public _write ( chunk: Buffer, encoding, cb ) {
		if ( this.socket.writable ) {
			console.log ( 'blockBuffer16 socket.write :', chunk.length )
			this.socket.write ( chunk )
			this.socket.resume ()
			return cb ()
		}
		console.log ( 'blockBuffer16 socket.writable false')
		return cb ()
	}
}
