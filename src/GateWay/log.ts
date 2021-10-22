import hexdump from 'hexdump-nodejs'
import colors from 'colors/safe'

export const logger = (...argv: any) => {
    const date = new Date ()
    let dateStrang = `[Gateway ${ date.getHours() }:${ date.getMinutes() }:${ date.getSeconds() }:${ date.getMilliseconds ()}] `
    return console.log ( dateStrang, ...argv )
}

export const hexDebug = ( buffer: Buffer, length: number= 256 ) => {
    console.log(colors.underline(colors.green(`TOTAL LENGTH [${ buffer.length }]`)))
    console.log(colors.grey( hexdump( buffer.slice( 0, length ))))
}