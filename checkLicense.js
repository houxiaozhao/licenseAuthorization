const NodeRSA = require('node-rsa');
const AES = require("crypto-js/aes");
const Utf8 = require('crypto-js/enc-utf8');
const ECB = require("crypto-js/mode-ecb")
const Pkcs7 = require("crypto-js/pad-pkcs7")
const fs = require('fs')
// const license = fs.readFileSync('./license_file/license').toString()
// const publicKey = fs.readFileSync('./license_file/publicKey.pem').toString()
const license = fs.readFileSync('./py/key/license').toString()
const publicKey = fs.readFileSync('./py/key/publicKey.pem').toString()
const aescfg = { mode: ECB, padding: Pkcs7 }

function checkLicense(license, publicKey) {
    try {
        const aesKey = Utf8.parse(license.substring(0, 16));
        console.log('aesKey', aesKey.toString());
        const encDataLength = parseInt(license.substring(16, 18), 16);
        console.log('encDataLength', encDataLength);
        const encData = license.substring(18, 18 + encDataLength);
        console.log('encData', encData);
        const sign = license.substring(18 + encDataLength);
        console.log('sign', sign);
        const key = new NodeRSA(publicKey, 'pkcs8-public-pem');
        if (!key.verify(encData, sign, 'base64', 'base64')) {
            console.log('验签失败');
            return false;
        }
        console.log('验签成功');
        const data = JSON.parse(AES.decrypt(encData, aesKey, aescfg).toString(Utf8));
        console.log('data', data);
        return true;
    } catch (error) {
        console.log(error);
        return false;
    }
}
checkLicense(license, publicKey)