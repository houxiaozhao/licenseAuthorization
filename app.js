const NodeRSA = require('node-rsa');
const randomString = require('random-string');
const Utf8 = require('crypto-js/enc-utf8');
const AES = require("crypto-js/aes");
const ECB = require("crypto-js/mode-ecb")
const Pkcs7 = require("crypto-js/pad-pkcs7")
const fs = require('fs')
const argv = require('yargs')
    .usage('Usage: $0 -appid [string] -hardware [string] -info [string]')
    .demand(['appid', 'hardware', 'info'])
    .alias('a', 'appid')
    .alias('h', 'hardware')
    .alias('i', 'info')
    .epilog('eapi授权程序')
    .describe('a', 'appid snd.808.eapi')
    .describe('h', '硬件id')
    .describe('i', '授权公司名称')
    .argv;
const authorization = {
    appid: argv.appid,
    issuedTime: parseInt(Date.now() / 1000),
    hardware: argv.hardware,
    customerInfo: argv.info
}
if (Buffer.from(JSON.stringify(authorization)).length > 150) {
    console.error('文本太长');
    return;
}
const aescfg = { mode: ECB, padding: Pkcs7 }

function getLicense(authorization, privateKey) {
    const aesKey = randomString({ length: 16 })
    const encData = AES.encrypt(Utf8.parse(JSON.stringify(authorization)), Utf8.parse(aesKey), aescfg).toString()
    const encDataLength = encData.length.toString(16)
    const key = new NodeRSA(privateKey, 'pkcs1-private-pem');
    const sign = key.sign(encData, 'base64', 'base64')
    console.log('aesKey', aesKey);
    console.log('encData', encData);
    console.log('encDataLength', encDataLength);
    console.log('sign', sign);
    const license = aesKey + encDataLength + encData + sign;
    return license
}
function checkLicense(license, publicKey) {
    try {
        const aesKey = Utf8.parse(license.substring(0, 16));
        const encDataLength = parseInt(license.substring(16, 18), 16);
        const encData = license.substring(18, 18 + encDataLength);
        const sign = license.substring(18 + encDataLength);
        const key = new NodeRSA(publicKey, 'pkcs8-public-pem');
        if (!key.verify(encData, sign, 'base64', 'base64')) {
            return false;
        }
        const data = JSON.parse(AES.decrypt(encData, aesKey, aescfg).toString(Utf8));
        console.log('data', data);
        return true;
    } catch (error) {
        return false;
    }
}
const key = new NodeRSA({ b: 1024 });
const publicKey = key.exportKey('public');
const privateKey = key.exportKey('private');
const license = getLicense(authorization, privateKey)
if (!checkLicense(license, publicKey)) {
    console.error('生成失败');
    return
}
// fs.writeFileSync('./key/privateKey.pem', privateKey)
if (!fs.existsSync('./key')) {
    fs.mkdirSync('./key')
}
fs.writeFileSync('./key/publicKey.pem', publicKey)
fs.writeFileSync('./key/license', license)
fs.writeFileSync('./key/appid', authorization.appid)
console.log('生成成功，查看key目录');