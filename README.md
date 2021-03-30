# Alacrity DApp Login

*Allow Alacrity DApps to handle login redirects from the Alacrity Companion Wallet and store relevant user data in local storage.*

## Usage 

    npm i alacrity-dapp-login --save

Install this node package to your decentralized application to handle login requests with Alacrity.

1. Add a "Login with Alacrity" button to your dApp with the link: 'alacrity://login/YOUR-DAPP-NAME'
2. This link should open the Alacrity Companion Wallet (assuming the wallet is installed)
3. Verify the login request on your wallet with your wallet pin
4. You will be redirected back to your dApp and prompted to decrypt login data with your wallet pin
5. Enter pin and the module will login with Alacrity and store all relevant user data in local storage under 'userData'
