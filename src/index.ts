import * as CryptoJS from "crypto-js";
import * as bip32 from 'bip32';
import { BIP32Interface } from 'bip32';
import { createHash, randomBytes } from 'crypto';
import { ECPair } from 'bitcoinjs-lib';
import { TokenSigner } from 'jsontokens'

const elliptic = require('elliptic');
const EC = new elliptic.ec('secp256k1');
const GAIA_HUB_URL_USER = 'https://rub.alacritys.net'
const TOKEN = 'https://handless-dapp.alacritys.net'

export default class DappLoginService {
    open(data : string, error? : boolean){
        let pin = null
        if (!error) pin = prompt("Decrypt login data with your pin from Alacrity Companion Wallet\n");
        else        pin = prompt("ERROR DECRYPTING: Please try again...\n\nDecrypt login data with your pin from Alacrity Companion Wallet\n");

        if (pin){
            let decrypted : any;
            try   { decrypted = JSON.parse(CryptoJS.AES.decrypt(data, pin).toString(CryptoJS.enc.Utf8)); }
            catch { console.log("DECRYPT FAILED, TRY AGAIN 1"); if (pin) this.open(data, true); }

            if (decrypted && decrypted.email && decrypted.password && decrypted.mnemonic){
                const xhr = new XMLHttpRequest();
                xhr.onload = function () {
                    if (xhr.status >= 200 && xhr.status < 300) {
                        const res = JSON.parse(xhr.responseText).data;
                        const userData : any = {};
                        const keys = [];

                        if (/ID-/g.test(res.account.Address)) {
                            const addresses = [];
                            const str = res.account.Address.slice(3);
                            addresses.push({ address: str, username: res.username });
                            userData.currentUser = res.username;
                            userData.address = addresses;
                            userData.defaultId = str;
                            userData.currentUser = res.username;
                            userData.account = [res.account];
                            keys.push({ keys: res.account.privateKey, userAddress: str });
                            userData.privateKey = keys;
                            userData.email = decrypted.email;
                        }

                        new Promise((resolve) => {
                            const xhr2 = new XMLHttpRequest();
                            xhr2.onload = function () {
                                const responseGAIA = JSON.parse(xhr2.responseText);

                                if(xhr2.status == 200) {
                                    userData.gaia = {
                                        gaiaHubConfig: responseGAIA[0].decodedToken.payload.claim.api.gaiaHubConfig.url_prefix,
                                        gaiaHubUrl: responseGAIA[0].decodedToken.payload.claim.api.gaiaHubUrl,
                                    }
                                    if (Object.prototype.hasOwnProperty.call(responseGAIA[0].decodedToken.payload.claim, "name"))
                                        userData.personName = responseGAIA[0].decodedToken.payload.claim.name

                                    if (userData.gaia.gaiaHubConfig.includes("https://gaia.aladinnetwork.org/")) 
                                        userData.gaia.gaiaHubConfig = 'https://eugaiahub.s3.eu-central-1.amazonaws.com/';
                                    
                                    if (userData.gaia.gaiaHubUrl.includes("https://rub.aladinnetwork.org")) 
                                        userData.gaia.gaiaHubUrl = 'https://rub.alacritys.net';
                                }
                                resolve(responseGAIA)
                            }
                            xhr2.open('GET', `https://eugaiahub.s3.eu-central-1.amazonaws.com/${res.account.Address.slice(3)}/profile.json?gaiaUrl=${res.account.Address.slice(3)}`, true);
                            xhr2.send();
                        }).then(async (responseGAIA : any)=>{
                            localStorage.setItem('mnemonicCode', JSON.stringify(res.mnemonicCode));
                            localStorage.setItem('userData', JSON.stringify(userData));

                            const node: BIP32Interface = bip32.fromBase58(res.account.appsNodeKey);
                                const appsNode = new AppsNode(node, res.account.salt);
                                const appPrivateKey = appsNode.getAppNode(TOKEN).getKey();
                                const compressedAppPublicKey = getPublicKeyFromPrivate( appPrivateKey.slice(0, 64) );
                                const privateKey = decryptAESKey(res.account.privateKey);
                                const associationToken = makeGaiaAssociationToken( await privateKey, compressedAppPublicKey );
    
                                const session = {
                                    version: "1.0.0",
                                    userData: {
                                        username: null,
                                        profile: {
                                            "@type": "Person",
                                            "@context": "http://schema.org",
                                            api: {
                                                gaiaHubConfig: { url_prefix: `${responseGAIA.status == 200 ? userData.gaia.gaiaHubUrl : GAIA_HUB_URL_USER}/hub/` },
                                                gaiaHubUrl: `${responseGAIA.status == 200 ? userData.gaia.gaiaHubUrl : GAIA_HUB_URL_USER}`,
                                            },
                                        },
                                        email: decrypted.email,
                                        decentralizedID: `did:btc-addr:${userData.address}`,
                                        identityAddress: privateKey,
                                        appPrivateKey,
                                        coreSessionToken: null,
                                        authResponseToken: "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJqdGkiOiI1ZDM3NTg5YS0xZTE4LTRjM2UtYTMyYy1iYWEwNGFlOWRlNmYiLCJpYXQiOjE1NzkzMjkyOTcsImV4cCI6MTU4MjAwNzY5NywiaXNzIjoiZGlkOmJ0Yy1hZGRyOjFDeDJnemJ3UHZVQmNveVpRZ1BCMXdlVDZQcjNkYnUybm4iLCJwcml2YXRlX2tleSI6IjdiMjI2OTc2MjIzYTIyNjQzODM5MzY2MzYzMzIzNzMwMzQ2MTM0NjUzNjYzNjEzMzMyMzM2MjMxNjEzNjM5MzI2NjY2NjI2NDY0MzkzOTIyMmMyMjY1NzA2ODY1NmQ2NTcyNjE2YzUwNGIyMjNhMjIzMDMzMzIzODY0MzczNTMyNjIzMzY2MzgzMzMyNjMzMzM0MzAzMzYzNjEzNzMyMzYzNjM1NjE2MzM3MzUzNTM0NjY2NDMwMzc2MTM2MzI2NjY1MzgzNzY1MzQ2NTM5NjI2MzM5MzU2MjYyNjE2NjY2NjUzNDY2MzQzNzM0NjM2MTYzMzgyMjJjMjI2MzY5NzA2ODY1NzI1NDY1Nzg3NDIyM2EyMjMxMzgzMDM1MzYzODM4MzEzOTMwNjQ2NDM4NjQzMjM4MzAzOTM5NjMzODMwMzIzNjM3MzgzNDYxNjU2MzYxMzkzNDMwMzAzNDY2MzczMzM3NjQ2NTYxNjE2NDMwMzczNDM4MzEzNDM1NjEzNTM1MzEzODM1NjE2NDM0NjM2MzY1NjM2NTM4NjUzNDY1NjI2NTMzMzMzOTM1NjM2MTY2MzIzMzMwMzQ2NDM2MzIzODM3MzQzNTY1MzAzODM0MzMzNjM5MzYzNTMyMzA2NjYxMzU2NjM2NjU2MTY2MzQzMjMwMzEzODM0MzYzMzY2MzI2NTM5NjM2MzMyMzI2MzYzNjIzNjM3MzYzODYyMzc2MjMxNjQzMDMyMzkzNDY0MzIzNTM0MzE2NjM2NjEzMjM2MzA2NDM3NjEzODMzNjQzNzYxMjIyYzIyNmQ2MTYzMjIzYTIyMzczOTM0NjQ2MzM5MzU2NjY0NjMzMjM2MzQ2MjM1MzIzNTYxMzA2NTMyMzMzODM5NjMzMjM5MzEzMDMxMzgzMDMxNjY2MzY0MzYzOTYxNjYzMDYyMzczNDY0MzA2MTYyNjYzOTM4MzIzOTYzMzgzNDY1MzI2NTY1MzM2NDY1NjUyMjJjMjI3NzYxNzM1Mzc0NzI2OTZlNjcyMjNhNzQ3Mjc1NjU3ZCIsInB1YmxpY19rZXlzIjpbIjAzZDU5Y2E2ZGJhNDk0OTYwMWQ1YjNlOWRkMzA3MTg5NjExNWM0ZWIzMGMzZmM0NGIxNGQ0N2JlOWFhY2RhZTc3MiJdLCJwcm9maWxlIjp7IkB0eXBlIjoiUGVyc29uIiwiQGNvbnRleHQiOiJodHRwOi8vc2NoZW1hLm9yZyIsImFwaSI6eyJnYWlhSHViQ29uZmlnIjp7InVybF9wcmVmaXgiOiJodHRwczovL2ZpbmFsZ2FpYS5hbGFkaW5uZXR3b3JrLm9yZy9odWIvIn0sImdhaWFIdWJVcmwiOiJodHRwczovL2ZpbmFsZ2FpYS5hbGFkaW5uZXR3b3JrLm9yZyJ9fSwidXNlcm5hbWUiOm51bGwsImNvcmVfdG9rZW4iOm51bGwsImVtYWlsIjpudWxsLCJwcm9maWxlX3VybCI6Imh0dHBzOi8vdG9kby1kYXBwLnMzLmFwLXNvdXRoLTEuYW1hem9uYXdzLmNvbS9JRC0xQ3gyZ3pid1B2VUJjb3laUWdQQjF3ZVQ2UHIzZGJ1Mm5uL3Byb2ZpbGUuanNvbiIsImh1YlVybCI6Imh0dHBzOi8vZmluYWxnYWlhLmFsYWRpbm5ldHdvcmsub3JnIiwiYWxhZGluQVBJVXJsIjoibnVsbC8vbnVsbCIsImFzc29jaWF0aW9uVG9rZW4iOiJleUowZVhBaU9pSktWMVFpTENKaGJHY2lPaUpGVXpJMU5rc2lmUS5leUpqYUdsc1pGUnZRWE56YjJOcFlYUmxJam9pTUROa09UQm1OVEZsTkRBeE9HVmtPVGxpT1RrMU5UWTROekk1TTJFMk1qUmtPRFkyTWpVd1pUazBZalkxTXpCbE5EWTFPVEE1TVRNMFl6WTNZamRoTkdGaklpd2lhWE56SWpvaU1ETmtOVGxqWVRaa1ltRTBPVFE1TmpBeFpEVmlNMlU1WkdRek1EY3hPRGsyTVRFMVl6UmxZak13WXpObVl6UTBZakUwWkRRM1ltVTVZV0ZqWkdGbE56Y3lJaXdpWlhod0lqb3hOakV3T0RZMU1qazNMamcyTml3aWFXRjBJam94TlRjNU16STVNamszTGpnMk5pd2ljMkZzZENJNkltVTNNVGRpTkRNMk1HVmxObUl4TWpJeE4yTXpOMkUyWmpGaE1HTmlNMlUxSW4wLkhsd2h4cEt2b0k4cGNSeVRHV0hLV2d3UHV5ZjQ5bUE2em53aWxhRlNhNDdBanN3Nm5lN0JjSVg0cks1YzV5YUVPalBaQkg2aXZ4bDRtbkNsMEY4U1JRIiwidmVyc2lvbiI6IjEuMy4xIn0.P1jQMG8DkAj7EcyQ35y5iu9oVA1ovo7UFjM8CRj25yXof5BbT1Hxj7Svm15WMCYBKPEpcjFp78tayvhzIyaqJA",
                                        hubUrl: `${responseGAIA.status == 200 ? userData.gaia.gaiaHubUrl : GAIA_HUB_URL_USER}`,
                                        gaiaAssociationToken: associationToken,
                                    }
                                }
                                localStorage.setItem('aladin-session', JSON.stringify(session));
                        })
                    } 
                    else console.log("Something went wrong...", xhr.responseText);
                };
                xhr.open('POST', 'https://euapi.alacritys.net/users/login');
                xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
                xhr.setRequestHeader("Accept", "*/*");
                xhr.send(JSON.stringify({ email: decrypted.email, mnemonic_code: decrypted.mnemonic, password: decrypted.password }));
            }
            else { console.log("DECRYPT FAILED, TRY AGAIN"); if (pin) this.open(data, true); }
        }
    }
}

class AppNode {
    hdNode;
    appDomain;
    constructor(hdNode : any, appDomain : any) {        
        this.hdNode = hdNode;
        this.appDomain = appDomain;
    }
    getKey() { return this.hdNode.__D.toString('hex'); }
} 
class AppsNode {
    hdNode;
    salt;
    constructor(appsHdNode : any, salt : any) {
        this.hdNode = appsHdNode;
        this.salt = salt;
    }
    getAppNode(appDomain : any) {
        const hash = createHash('sha256').update(`${appDomain}${this.salt}`).digest('hex');
        const appIndex = hashCode(hash);
        const appNode = this.hdNode.deriveHardened(appIndex);
        return new AppNode(appNode, appDomain);
    }
}
function hashCode(string : any) {
    let hash = 0;
    if (string.length === 0) return hash;
    for (let i = 0; i < string.length; i++) {
        const character = string.charCodeAt(i);
        hash = (hash << 5) - hash + character;
        hash &= hash;
    }
    return hash & 0x7fffffff;
}
function getPublicKeyFromPrivate(privateKey: string) {
    const keyPair = ECPair.fromPrivateKey(Buffer.from(privateKey, 'hex'))
    return keyPair.publicKey.toString('hex')
}
async function decryptAESKey(encryptedKey : any) {
    try {
        var bytes = await CryptoJS.AES.decrypt(encryptedKey.toString(), "CoVid-19");
        var decryptedData = await bytes.toString(CryptoJS.enc.Utf8);
        if (decryptedData == "") return false
        return decryptedData
    } catch (err) { return err }
}
function makeGaiaAssociationToken(
        secretKeyHex: string,
        childPublicKeyHex: string ){

    const LIFETIME_SECONDS = 365 * 24 * 3600;
    const signerKeyHex = secretKeyHex.slice(0, 64);
    const compressedPublicKeyHex = getPublicKeyFromPrivate(signerKeyHex);
    const salt = randomBytes(16).toString('hex');
    const date = new Date()
    const payload = {
        childToAssociate: childPublicKeyHex,
        iss: compressedPublicKeyHex,
        exp: LIFETIME_SECONDS + date.getTime() / 1000,
        iat: Date.now() / 1000,
        salt,
    };
    const token = new TokenSigner('ES256K', signerKeyHex).sign(payload);
    return token;
}