
interface IinputData extends imapConnect {

    clientFolder: string
    serverFolder: string
    randomPassword: string
    uuid: string
}
interface imapConnect {
    imapServer: string
    imapUserName: string
    imapUserPassword: string
    imapPortNumber: string
    imapSsl: boolean
    imapIgnoreCertificate: boolean
}
interface VE_IPptpStream {
    type?: string;
    buffer: string;
    host: string;
    port: number;
    cmd: number;
    ATYP: number;
    uuid?: string;
    length?:number;
    randomBuffer?: Buffer
    ssl: boolean
}

interface dnsAddress {
	address: string
	family: number
	expire: Date
	connect: Date []
}
interface domainData {
	dns: dnsAddress[]
	expire: number
}
interface iTransferData {
    startDate: string
    transferDayLimit: number
    transferMonthly: number
    account: string
    resetTime: string
    usedDayTransfer: number
    productionPackage: string
    usedMonthlyTransfer: number
    availableDayTransfer: number
    availableMonthlyTransfer: number
    usedMonthlyOverTransfer: number
    uploaded?: number
    downloaded?: number
    power: number
    timeZoneOffset: number
    expire: string
    isAnnual: boolean
    paidID: string[]
    automatically: boolean
    promo: CoPromo[]
}
interface CoPromo {
    datePromo: number
    pricePromo: number
    promoDetail: string[]
    promoFor: string[]
}

interface IConnectCommand {
    region: string
    account: string
    imapData: IinputData
    connectType: number
    transferData?: iTransferData
    error?: number
    dockerName?: string
    randomPassword?: string
    runningDocker?: string
    AllDataToGateway?: boolean
    fingerprint: string
    gateWayIpAddress: string
    gateWayPort?: number
    totalUserPower?: number
    requestContainerEachPower?: number
    connectPeer?: string
    requestRegions?: string[]
    multipleGateway?: multipleGateway[]
    requestMultipleGateway?: number
    containerUUID?: string
    peerUuid?: string
    localServerIp?: string[]
    localServerPort: string
    webWrt?: boolean
    requestPortNumber: string
    globalIpAddress: string
}

interface multipleGateway {
    gateWayIpAddress: string
    gateWayPort: number
    dockerName: string
    password: string
}

interface fileBlokeInfo {
	salt: Buffer
	iv: Buffer,
	iterations: number
	keylen: number
	digest: string
	derivedKey: Buffer
	algorithm: string
	files: string[]
	getAuthTag: string[]

}