
import * as Crypto from 'crypto'
const idleHoldTime = 1000 * 60 * 30
export default class container {
    public password = this.client.randomPassword
    private hashPool = []
    public fingerprint = this.client.fingerprint
    public upload = 0
    public download = 0
    private idleTime: NodeJS.Timer = null
    
	constructor ( private client: IConnectCommand, private dataOver: () => void ) {
        client.transferData.uploaded = client.transferData.downloaded = 0

        this.resetIdle ()
    }

    private resetIdle () {
        clearTimeout ( this.idleTime )
        this.idleTime = setTimeout (() => {
            console.log ( `resetIdle time out!`)
            return this.dataOver ()
        }, idleHoldTime )
    }
    
    public HashCheck ( data: Buffer ) {
        const hasdD = Crypto.createHash ( 'md5' ).update ( data ).digest ('hex')
        const index = this.hashPool.findIndex ( n => { return n === hasdD })
        if ( index < 0 ) {
            this.hashPool.push ( hasdD )
            return false
        }

        return true
    }


    public countData ( length: number, upload: boolean ) {
        this.resetIdle ()
        return upload ? this.upload += length : this.download += length
    }

    public stopContainer () {
        return this.dataOver ()
    }
}