var CryptoJS = require("crypto-js");

export class DappLoginService {
    constructor(){}

    open(data : any, error? : boolean){
        let pin = null
        if (!error) pin = prompt("Decrypt login data with your pin from Alacrity Companion Wallet\n");
        else        pin = prompt("ERROR DECRYPTING: Please try again...\n\nDecrypt login data with your pin from Alacrity Companion Wallet\n");

        if (pin){
            var decrypted : any;
            try   { decrypted = JSON.parse(CryptoJS.AES.decrypt(data, pin).toString(CryptoJS.enc.Utf8)); }
            catch { console.log("DECRYPT FAILED, TRY AGAIN 1"); if (pin) this.open(data, true); }

            if (decrypted && decrypted.email && decrypted.password && decrypted.mnemonic){
                var xhr = new XMLHttpRequest();
                xhr.onload = function () {
                    if (xhr.status >= 200 && xhr.status < 300) {
                        var res = JSON.parse(xhr.responseText).data;
                        console.log(res);
                        var userData : any = {};
                        var keys = [];

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
                            var xhr2 = new XMLHttpRequest();
                            xhr2.onload = function () {
                                var responseGAIA = JSON.parse(xhr2.responseText);
                                console.log("responseGAIA", responseGAIA);

                                if(xhr2.status == 200) {
                                    userData.gaia = {
                                        gaiaHubConfig: responseGAIA[0].decodedToken.payload.claim.api.gaiaHubConfig.url_prefix,
                                        gaiaHubUrl: responseGAIA[0].decodedToken.payload.claim.api.gaiaHubUrl,
                                    }
                                    if (responseGAIA[0].decodedToken.payload.claim.hasOwnProperty('name'))
                                        userData.personName = responseGAIA[0].decodedToken.payload.claim.name

                                    if (userData.gaia.gaiaHubConfig.includes("https://gaia.aladinnetwork.org/")) 
                                        userData.gaia.gaiaHubConfig = 'https://eugaiahub.s3.eu-central-1.amazonaws.com/';
                                    
                                    if (userData.gaia.gaiaHubUrl.includes("https://rub.aladinnetwork.org")) 
                                        userData.gaia.gaiaHubUrl = 'https://rub.alacritys.net';
                                }
                                resolve(null)
                            }
                            xhr2.open('GET', `https://eugaiahub.s3.eu-central-1.amazonaws.com/${res.account.Address.slice(3)}/profile.json?gaiaUrl=${res.account.Address.slice(3)}`, true);
                            xhr2.send();
                        }).then(()=>{
                            // console.log('userData', userData)
                            localStorage.setItem('mnemonicCode', JSON.stringify(res.mnemonicCode));
                            localStorage.setItem('userData', JSON.stringify(userData));
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
