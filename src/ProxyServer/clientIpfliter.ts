
import { exec } from 'child_process'

const iptables = ( remoteAddress: string, proxyPORT: string, CallBack ) => {
	
	return exec(`iptables -I INPUT 1 -s ${ remoteAddress } -m tcp -p tcp --dport ${ proxyPORT } -j ACCEPT`, err => {
		return CallBack ( err )
	}) 
}
export default class clientFilter {
    private server
    constructor ( private password: string, private listenPORT: string, private proxyPORT: string ) {
        this.startServer ()
    }
    private startServer () {
		const express = require ('express')
        const app = express()
        const securityPath = '/' + this.password

        app.get ( securityPath, ( req, res ) => {
			const _ipaddress: string = req.socket.remoteAddress.split (':')
			const ipaddress = _ipaddress[ _ipaddress.length - 1]

			return iptables ( ipaddress, this.proxyPORT, err => {
				if ( err ) {
					return res.end (`System Iptables Error!\n${ err.message }`)
				}
				return res.end (`Your IP address [${ ipaddress }] success!\n`)
			})
			
        })

		app.get ('*', () => {
			
		})

        app.listen ( this.listenPORT, () => {
            return console.table ([
                { 'QTGate IP address filter server start at': `http://localhost:${ this.listenPORT }/${ this.password }` }
            ])
        })
    }
}