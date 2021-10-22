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

export const encrypt = ( text: Buffer, masterkey: string, CallBack ) => {
	let salt = null
	Async.waterfall ([
		next => crypto.randomBytes ( 64, next ),
		( _salt, next ) => {
			salt = _salt
			crypto.pbkdf2 ( masterkey, salt, 2145, 32, 'sha512', next )
		}
	], ( err, derivedKey ) => {
		if ( err )
			return CallBack ( err )
		
		crypto.randomBytes ( 12, ( err1, iv ) => {
			if ( err1 )
				return CallBack ( err1 )
			
			const cipher = crypto.createCipheriv ( 'aes-256-gcm', derivedKey, iv );
		
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
		crypto.pbkdf2 ( masterkey, salt , 2145, 32, 'sha512', ( err, derivedKey ) => {
			
			if ( err )
				return CallBack ( err )
			// AES 256 GCM Mode
			try {
				const decipher = crypto.createDecipheriv ( 'aes-256-gcm', derivedKey, iv )
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
	
	const _buffer = new Buffer ( 6 )
	_buffer.fill ( 0 )
	_buffer.writeUInt8 ( bit0, 0 )
	_buffer.writeUInt32BE ( _serial, 1 )

	const uuid = new Buffer ( id, 'utf8' )
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

export class encryptStream extends Stream.Transform {
	private salt: Buffer
	private iv: Buffer
	public ERR: Error = null
	private first = true
	public derivedKey: Buffer = null
	public dataCount = false
	private BlockBuffer ( _buf: Buffer ) {
		return Buffer.from( _buf.length.toString( 16 ).toUpperCase() + '\r\n', 'utf8' )
	}

	constructor ( public id: string, private password: string, private random: number, public download:( n: number ) => void, private httpHeader : ( str: string ) => Buffer, CallBack ) {
		super ()
		Async.waterfall ([
			next => crypto.randomBytes ( 64, next ),
			( _salt, next ) => {
				this.salt = _salt
				crypto.randomBytes ( 12, next )
			},
			( _iv, next ) => {
				this.iv = _iv
				crypto.pbkdf2 ( password, this.salt, 2145, 32, 'sha512', next )
			}
		], ( err, derivedKey ) => {
			if ( err ) {
				console.log (colors.red(`encryptStream init error ${ err.message }`))
				return this.ERR = err
			}
				
			this.derivedKey = derivedKey
			return CallBack ( err )
		})
	}
	
	public _transform ( chunk: Buffer, encode, cb ) {

		logger (colors.green(` ${ this.id } encryptStream <--- Target`))
		hexDebug(chunk)
		const cipher = crypto.createCipheriv ( 'aes-256-gcm', this.derivedKey, this.iv )

		let _text = Buffer.concat ([ Buffer.alloc ( 4, 0 ) , chunk ])

		_text.writeUInt32BE ( chunk.length, 0 )

		if ( chunk.length < this.random ) {
			_text = Buffer.concat ([ _text, Buffer.allocUnsafe ( Math.random() * 1000 )])
		}

		const _buf = Buffer.concat ([ cipher.update ( _text ), cipher.final ()])
		const _buf1 = Buffer.concat ([ cipher.getAuthTag (), _buf ])

		if ( this.dataCount ){
			//console.log ( `**** encryptStream ID[${ this.id }] dataCount is [true]! data.length`)
			this.download ( _buf1.length )
		}
			
		
		if ( this.first ) {

			this.first = false
			const black = Buffer.concat ([ this.salt, this.iv, _buf1 ]).toString ( 'base64' )
			if ( ! this.httpHeader ) {
				
				const _buf4 = Buffer.from ( black, 'utf8')
				const _buffer = Buffer.concat ([ HTTP_HEADER, this.BlockBuffer ( _buf4 ), _buf4, EOF ])
				logger ( colors.green(`encryptStream have no httpHeader!  first client <--- Target _buffer = [${ _buffer.length }]`))

				return cb ( null, _buffer )
			}
			const _data = this.httpHeader ( black )
			logger (colors.green(`encryptStream first to client client <--- Target _buffer = [${ _data.length }]`))

			return cb ( null, _data )

		}
		logger(colors.blue(`${ this.id } encryptStream send data`))
		hexDebug(_buf1)
		const _buf2 = _buf1.toString ( 'base64' )
		return cb ( null, _buf2 )
	}
}

export class decryptStream extends Stream.Transform {
	private first = true
	private salt: Buffer
	private iv: Buffer
	public dataCount = true
	private derivedKey: Buffer = null
	private decipher: crypto.Decipher = null

	private _decrypt ( _buf: Buffer, CallBack ) {
		return crypto.pbkdf2 ( this.password, this.salt , 2145, 32, 'sha512', ( err, derivedKey ) => {
			if ( err ) {
				console.log ( `**** decryptStream crypto.pbkdf2 ERROR: ${ err.message }` )
				return CallBack ( err )
			}
			this.derivedKey = derivedKey

			try {
				this.decipher = crypto.createDecipheriv ( 'aes-256-gcm', this.derivedKey, this.iv )
				// @ts-ignore
				this.decipher.setAuthTag ( _buf.slice ( 0, 16 ))
			} catch ( ex ) {
				return CallBack ( new Error (`class decryptStream firstProcess crypto.createDecipheriv Error chunk [${ _buf.toString()}]`) )
			}

			let _Buf = null

			try {
				_Buf = Buffer.concat ([ this.decipher.update ( _buf.slice ( 16 )) , this.decipher.final () ])
			} catch ( e ) {
				return CallBack ( new Error (`class decryptStream firstProcess _decrypt error. chunk.length = [${ _buf.length }]`) )
			}

			const length = _Buf.readUInt32BE (0) + 4
			const uuu = _Buf.slice ( 4, length )
			logger(colors.blue(`${ this.id } decryptStream first success!`))
			hexDebug (uuu)
			return  CallBack ( null, uuu )
			
		})
	}
	public firstProcess ( chunk: Buffer, CallBack: ( err?: Error, text?: Buffer ) => void ) {
		if ( chunk.length < 76 ) {
			return CallBack (new Error (`Unknow connect!`))
		}
		this.first = false
		this.salt = chunk.slice ( 0, 64 )
		this.iv = chunk.slice ( 64, 76 )
		return this._decrypt (chunk.slice ( 76 ), CallBack)
	}

	constructor ( public id: string, private password: string, public upload: ( n: number ) => void ) {
		super ()
	}

	public _transform ( chunk: Buffer, encode, cb ) {
		
			if ( this.dataCount ){
				//console.log ( `decryptStream id [${ this.id }] dataCount = [TRUE]!`)
			 	this.upload ( chunk.length )
			}
				
			if ( this.first ) {
				return this.firstProcess ( chunk, cb )
			}
			const _chunk = Buffer.from(chunk.toString(), 'base64')
			hexDebug( _chunk )
			return this._decrypt (_chunk, cb)
		
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

export class getDecrypGatwayStreamFromHttp extends Stream.Transform {

	private text = ''

	private formatErr ( text: string ) {
		const log = 'getDecryptRequestStreamFromHttp format ERROR:\n*****************************\n' + text + '\r\n'
		console.log ( log )
		this.saveLog ( log )
	}

	constructor ( private saveLog: ( str: string ) => void ) { super ()}

	public _transform ( chunk: Buffer, encode, cb ) {
		
		this.text += chunk.toString ( 'utf8' )
		
		const block = this.text.split ( '\r\n\r\n' )
		
		while ( block.length > 1 ) {

			const blockText = block.shift ()

			if ( ! blockText.length )
				continue
				
			if ( /^GET /i.test ( blockText )) {
				
				const _line = blockText.split ( '\r\n' )[ 0 ]
				
				const _url = _line.split ( ' ' )
				
				if ( _url.length < 2 ) {
					if ( block.length > 1 ) {
						this.formatErr ( blockText )
						return this.unpipe ()
					}
					this.text = blockText
					return cb ()
				}
				const text = Buffer.from ( _url[1].slice ( 1 ), 'base64' )
				this.push ( text )
				continue
			}

			if ( /^POST /i.test ( blockText )) {

				if ( block.length > 0 ) {
					const header = blockText.split ( '\r\n' )

					const _length = header.findIndex ( n => {
						return /^Content-Length: /i.test ( n )
					})
					
					if ( _length === -1 ) {
						this.formatErr ( blockText )
						return this.unpipe ()
					}

					const lengthString = header [ _length ].split ( ' ' )
					if ( lengthString.length !== 2 ) {
						this.formatErr ( blockText )
						return this.unpipe ()
					}

					const length = parseInt ( lengthString[ 1 ])
					if ( ! length ) {
						this.formatErr ( blockText )
						return this.unpipe ()
					}

					const _text = block.shift ()
					if ( length !== _text.length ) {
						const log = `${ blockText }\r\n\r\n${ _text }`
						if ( block.length > 0 ) {
							this.formatErr ( log )
							return this.unpipe ()
						}
						this.text = log
						return cb ()
					}

					this.push ( Buffer.from ( _text, 'base64' ))
					continue
				}

				this.text = blockText
				return cb ()
			}
		}
		
		this.text = block[0]
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


