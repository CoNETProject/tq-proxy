export const logger = (...argv: any) => {
    const date = new Date ()
    let dateStrang = `[Gateway ${ date.getHours() }:${ date.getMinutes() }:${ date.getSeconds() }:${ date.getMilliseconds ()}] `
    return console.log ( dateStrang, ...argv )
}