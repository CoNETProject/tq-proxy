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

import * as Stream from 'stream'
import HttpHeader from './httpProxy'
import { logger } from './log'
import { inspect } from 'util'


export class blockRequestData extends Stream.Transform {
    private temp = Buffer.from ('')
    private startTime = new Date().getTime ()
    private timeOut = null
    private first = true
	public headers: HttpHeader = null
	public part0 = ''
    constructor ( private allowedAddress: boolean, timeout: number ) {
        super ()
        if ( timeout ) {
            this.timeOut = setTimeout (() => {
                this.unpipe ()
            }, timeout )
        }
    }

    public _transform ( chunk: Buffer, encode, cb ) {

        this.temp = Buffer.concat ([ this.temp, chunk ], this.temp.length + chunk.length )

        if ( this.temp.toString().split ('\r\n\r\n').length < 2 ) {
            return cb ()
        }

		const httpHeader = new HttpHeader ( this.temp )
        if (!this.part0) {
			this.part0 = this.temp.toString ()
		}
        //      have not http format request
        if ( ! httpHeader.isHttpRequest ) {
            
            logger('*************** SKIP unformat data **********************')
            logger ( inspect ( {HEADER: this.part0 }, false, 3, true ))
            httpHeader._parts.shift ()
            this.temp = Buffer.from ( httpHeader._parts.join ('\r\n\r\n'), 'utf8' )
            return this._transform ( Buffer.from (''), encode, cb )
        }

        if ( ! this.allowedAddress ) {
            logger (inspect ({ NOT_Allow_ADDRESS: this.part0 }) )
            return cb ( new Error ('404'))
        }

        if (! httpHeader.isGet && ! httpHeader.isPost ) {
            
            console.log ('************* unknow httpHeader   **********')
			logger ( inspect ( { UnKnow_HEADER: this.part0 }, false, 3, true ))
            httpHeader._parts.shift ()
            this.temp = Buffer.from ( httpHeader._parts.join ( '\r\n\r\n' ), 'utf8' )
            return this._transform ( Buffer.from (''), encode, cb )
        }

        if ( this.timeOut ) {
            clearTimeout ( this.timeOut )
            this.timeOut = null
        }

        if ( httpHeader.isGet ) {
			if ( this.first ) {
				
				const split_space = httpHeader._parts[0].split (' ')[1]
				if ( split_space === '/' ) {
					logger ( inspect ( { error: 'Have no path!', pathname: split_space, headers: httpHeader._parts }, false, 3, true ))
					return cb (new Error ('200'))
				}
			}
            const ret = Buffer.from ( httpHeader.Url.path.substr (1), 'base64' )
            httpHeader._parts.shift ()
            this.temp = Buffer.from ( httpHeader._parts.join ('\r\n\r\n'), 'utf8' )
            this.push ( ret )
            return this._transform ( Buffer.from (''), encode, cb )
        }

        if ( httpHeader._parts.length < 3 ) {
            return cb ()
        }
        
        const ret = Buffer.from ( httpHeader.PostBody, 'base64' )

        if ( !ret ) {     
            console.log ('***************** POST get data ERROR ********************')
            logger ( inspect({HEADER: this.part0 }, false, 3, true))
            
            httpHeader._parts.shift ()
            httpHeader._parts.shift ()

            this.temp = Buffer.from ( httpHeader._parts.join ( '\r\n\r\n' ), 'utf8' )
            return this._transform ( Buffer.from (''), encode, cb )
        }
        this.push ( ret )
        httpHeader._parts.shift ()
        httpHeader._parts.shift ()

        this.temp = Buffer.from ( httpHeader._parts.join ('\r\n\r\n'), 'utf8' )
        return this._transform ( Buffer.from (''), encode, cb )
    }
       
    
}