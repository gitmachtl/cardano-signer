# Tool to sign data with a Cardano-Secret-Key // verify data with a Cardano-Public-Key // generate CIP-8 & CIP-36 data

<img src="https://user-images.githubusercontent.com/47434720/190806957-114b1342-7392-4256-9c5b-c65fc0068659.png" align=right width=40%></img>

### What can cardano-signer sign?
* **Sign** any hexdata, textdata or binaryfile with a provided normal or extended secret key. The key can be provided in hex, bech or file format. The signing output is a signature in hex- or json-format, also the public key of the provided secret key for verification.
* Sign payloads in **CIP-8** mode. The signing output is a signature in hex format and also the public key of the provided secret key for verification. The output can also be set to be in json format which will also show additional data (--json-extended).
* Generate and sign **Catalyst registration/delegation/deregistration** metadata in **CIP-36** mode. This also includes relatively weighted voting power delegation. The output is the registration/delegation or deregistraton data in json or cborHex-format and/or a binary cbor file, which can be transmitted on chain as it is.

### What can cardano-signer verify?
* **Verify** a signature for any hexdata, textdata or binaryfile together with a provided public key. Also an optional address can be verified against the given public key. The key can be provided in hex, bech or file format. The verification output is true(exitcode=0) or false(exitcode=1) as a console output or in json-format.

<br>
<br>

## Usage

``` console

$ ./cardano-signer help

cardano-signer 1.10.1

Signing a hex/text-string or a binary-file:

   Syntax: cardano-signer sign
   Params: --data-hex "<hex>" | --data "<text>" | --data-file "<path_to_file>"
                                                                data/payload/file to sign in hex-, text- or binary-file-format
           --secret-key "<path_to_file>|<hex>|<bech>"           path to a signing-key-file or a direct signing hex/bech-key string
           [--address "<bech_address>"]                         optional address check against the signing-key (bech format like 'stake1..., addr1...')
           [--json | --json-extended]                           optional flag to generate output in json/json-extended format
           [--out-file "<path_to_file>"]                        path to an output file, default: standard-output
   Output: "signature_hex + publicKey_hex" or JSON-Format


Signing a payload in CIP-8 mode:

   Syntax: cardano-signer sign --cip8
   Params: --data-hex "<hex>" | --data "<text>" | --data-file "<path_to_file>"
                                                                data/payload/file to sign in hex-, text- or binary-file-format
           --secret-key "<path_to_file>|<hex>|<bech>"           path to a signing-key-file or a direct signing hex/bech-key string
           --address "<bech_address>"                           signing address (bech format like 'stake1..., stake_test1...')
           [--testnet-magic [xxx]]                              optional flag to switch the address check to testnet-addresses, default: mainnet
           [--json | --json-extended]                           optional flag to generate output in json/json-extended format
           [--out-file "<path_to_file>"]                        path to an output file, default: standard-output
   Output: "signature_hex + publicKey_hex" or JSON-Format


Signing a catalyst registration/delegation or deregistration in CIP-36 mode:

   Syntax: cardano-signer sign --cip36
   Params: [--vote-public-key "<path_to_file>|<hex>|<bech>"     public-key-file(s) or public hex/bech-key string(s) to delegate the votingpower to (single or multiple)
           --vote-weight <unsigned_int>]                        relative weight of each delegated votingpower, default: 100% for a single delegation
           --secret-key "<path_to_file>|<hex>|<bech>"           signing-key-file or a direct signing hex/bech-key string of the stake key (votingpower)
           --rewards-address "<bech_address>"                   rewards payout address (bech format like 'addr1..., addr_test1...')
           [--nonce <unsigned_int>]                             optional nonce value, if not provided the mainnet-slotHeight calculated from current machine-time will be used
           [--vote-purpose <unsigned_int>]                      optional parameter (unsigned int), default: 0 (catalyst)
           [--deregister]                                       optional flag to generate a deregistration (no --vote-public-key/--vote-weight/--rewards-address needed
           [--testnet-magic [xxx]]                              optional flag to switch the address check to testnet-addresses, default: mainnet
           [--json | --json-extended]                           optional flag to generate output in json/json-extended format, default: cborHex(text)
           [--out-file "<path_to_file>"]                        path to an output file, default: standard-output
           [--out-cbor "<path_to_file>"]                        path to write a binary metadata.cbor file to
   Output: Registration-Metadata in JSON-, cborHex-, cborBinary-Format


Verifying a hex/text-string or a binary-file via signature + publicKey:

   Syntax: cardano-signer verify
   Params: --data-hex "<hex>" | --data "<text>" | --data-file "<path_to_file>"
                                                                data/payload/file to verify in hex-, text- or binary-file-format
           --signature "<hex>"                                  signature in hexformat
           --public-key "<path_to_file>|<hex>|<bech>"           path to a public-key-file or a direct public hex/bech-key string
           [--address "<bech_address>"]                         optional address check against the public-key (bech format like 'stake1..., addr1...')
           [--json | --json-extended]                           optional flag to generate output in json/json-extended format
           [--out-file "<path_to_file>"]                        path to an output file, default: standard-output
   Output: "true/false" (exitcode 0/1) or JSON-Format

```

![image](https://user-images.githubusercontent.com/47434720/201514401-f70ccce4-8748-497f-a033-7b1fbc662ef3.png)


<br>
<br>

## Examples - Signing data in normal mode

### Sign text-data with a KEY-FILE (.skey)
``` console
cardano-signer sign --data "this is a test payload :-)" \
		    --secret-key test.skey
```
Output - Signature & publicKey (hex) :
```
8a5fd6602094407b7e5923aa0f2694f8cb5cf39f317a61059fdc572e24fc1c7660d23c04d46355aed78b5ec35ae8cad1433e7367bb874390dfe46ed155727a08 57758911253f6b31df2a87c10eb08a2c9b8450768cb8dd0d378d93f7c2e220f0
```
You can generate a nice json output via the `--json` flag
``` console
cardano-signer sign --data "this is a test payload :-)" \
                    --secret-key test.skey \
		    --json
```
``` json
{ 
  "signature": "8a5fd6602094407b7e5923aa0f2694f8cb5cf39f317a61059fdc572e24fc1c7660d23c04d46355aed78b5ec35ae8cad1433e7367bb874390dfe46ed155727a08",
  "publicKey": "57758911253f6b31df2a87c10eb08a2c9b8450768cb8dd0d378d93f7c2e220f0" 
}
```
You can generate a more detailed json output via the `--json-extended` flag
``` console
cardano-signer sign --data "this is a test payload :-)" \
                    --secret-key test.skey \
		    --json-extended
```
``` json
{
  "workMode": "sign",
  "signDataHex": "7468697320697320612074657374207061796c6f6164203a2d29",
  "signature": "8a5fd6602094407b7e5923aa0f2694f8cb5cf39f317a61059fdc572e24fc1c7660d23c04d46355aed78b5ec35ae8cad1433e7367bb874390dfe46ed155727a08",
  "secretKey": "e8ddb1cfc09e163915e6c28fcb5fbb563bfef57201857e15288b67abbd91e4441e5fa179a8f90da1684ba5aa310da521651d2ce20443f149f8ca9e333a96dabc",
  "publicKey": "57758911253f6b31df2a87c10eb08a2c9b8450768cb8dd0d378d93f7c2e220f0"
}
```
You can also do an optional address check, if the address belongs to the key.
``` console
cardano-signer sign --data "this is a test payload :-)" \
                    --secret-key test.skey \
		    --json-extended \
		    --address "addr1v9ux8dwy800s5pnq327g9uzh8f2fw98ldytxqaxumh3e8kqumfr6d"
```
If the address is wrong you will get an error like:
```
Error: The address 'addr1v9ux8dwy800s5pnq327g9uzh8f2fw98ldytxqaxumh3e8kqumfr6d' does not belong to the provided secret key.
```
If the address is correct, cardano-signer outputs like normal. In case of the detailed json output it also includes the address.
``` json
{
  "workMode": "sign",
  "signDataHex": "7468697320697320612074657374207061796c6f6164203a2d29",
  "address": "addr1v9ux8dwy800s5pnq327g9uzh8f2fw98ldytxqaxumh3e8kqumfr6d",
  "signature": "8a5fd6602094407b7e5923aa0f2694f8cb5cf39f317a61059fdc572e24fc1c7660d23c04d46355aed78b5ec35ae8cad1433e7367bb874390dfe46ed155727a08",
  "secretKey": "e8ddb1cfc09e163915e6c28fcb5fbb563bfef57201857e15288b67abbd91e4441e5fa179a8f90da1684ba5aa310da521651d2ce20443f149f8ca9e333a96dabc",
  "publicKey": "57758911253f6b31df2a87c10eb08a2c9b8450768cb8dd0d378d93f7c2e220f0"
}
```

> :bulb: For **verification**, check out the [Examples](#examples---verification) below too!

<br>

### Sign hex-data with a KEY-HEXSTRING
``` console
cardano-signer sign \
      --data-hex "8f21b675423a65244483506122492f5720d7bd35d70616348089678ed4eb07a9" \
      --secret-key "c14ef0cc5e352446d6243976f51e8ffb2ae257f2a547c4fba170964a76501e7a"
```
Output - Signature & publicKey (hex) :
```
ca3ddc10f845dbe0c22875aaf91f66323d3f28e265696dcd3c56b91a8e675c9e30fd86ba69b9d1cf271a12f7710c9f3385c78cbf016e17e1df339bea8bd2db03 9be513df12b3fabe7c1b8c3f9fab0968eb2168d5689bf981c2f7c35b11718b27
```
You can also write out to a file of course.
``` console
cardano-signer sign \
      --out-file mySignature.txt \
      --data-hex "8f21b675423a65244483506122492f5720d7bd35d70616348089678ed4eb07a9" \
      --secret-key "c14ef0cc5e352446d6243976f51e8ffb2ae257f2a547c4fba170964a76501e7a"
```
No visible output was generated to the stdout, but Signature+publicKey was written to the file mySignature.txt<br>

Here are two examples for invalid input secret keys:
``` console
cardano-signer sign \
      --data-hex "8f21b675423a65244483506122492f5720d7bd35d70616348089678ed4eb07a9" \
      --secret-key "c14ef0cc5e352446d6243976f51e8ffb2ae257f2a547c4fba170964a"
```
```
Error: Invalid normal secret key
```
``` console
cardano-signer sign \
      --data-hex "8f21b675423a65244483506122492f5720d7bd35d70616348089678ed4eb07a9" \
      --secret-key "c14ef0cc5e352446d6243976f51e8ffb2ae257f2a547c4fba170964a76501e7a88afe88fa8f888544e6f5a5f555e5faf6f6f"
```
```
Error: Invalid extended secret key
```

<br>

### Sign hex-data with a KEY-FILE (.skey)
``` console
cardano-signer sign \
      --data-hex "8f21b675423a65244483506122492f5720d7bd35d70616348089678ed4eb07a9" \
      --secret-key owner.staking.skey
```
Output - Signature & publicKey (hex) :
```
ca3ddc10f845dbe0c22875aaf91f66323d3f28e265696dcd3c56b91a8e675c9e30fd86ba69b9d1cf271a12f7710c9f3385c78cbf016e17e1df339bea8bd2db03 9be513df12b3fabe7c1b8c3f9fab0968eb2168d5689bf981c2f7c35b11718b27
```
``` console
cardano-signer sign \
      --data-hex "8f21b675423a65244483506122492f5720d7bd35d70616348089678ed4eb07a9" \
      --secret-key owner.staking.vkey
Error: The file 'owner.staking.vkey' is not a signing/secret key json
```

<br>

### Sign a file with a KEY-FILE (.skey)
``` console
cardano-signer sign --data-file test.txt --secret-key test.skey
```
Output - Signature & publicKey (hex) :
```
caacb18c46319f55b932efa77357f14b66b27aa908750df2c91800dc59711015ea2e568974ac0bcabf9b1c4708b877c2b94a7658c2dcad78b108049062572e09 57758911253f6b31df2a87c10eb08a2c9b8450768cb8dd0d378d93f7c2e220f0
```

<br>

## Examples - Signing data in CIP-8 mode

### Sign some text-data payload

``` console
cardano-signer sign --cip8 \
      --address "stake_test1uqt3nqapz799tvp2lt8adttt29k6xa2xnltahn655tu4sgc6asaqg" \
      --data '{"choice":"Yes","comment":"","network":"preview","proposal":"2038c417d112e005ef61c95d710ee62184a6c177d18b2da891f97cefae4f8535","protocol":"SundaeSwap","title":"Test Proposal - Tampered","version":"1","votedAt":"3137227","voter":"stake_test1uqt3nqapz799tvp2lt8adttt29k6xa2xnltahn655tu4sgc6asaqg"}' \
      --secret-key myStakeKey.skey \
      --testnet-magic 1
```
Output - Signature & publicKey (hex) :
```
5b2e7ac3fbe3cec1540f98fcc29c1ab63778e14a653a2328b2e56af6fd2a714540708e5f3e19670b9b867151c7dfb75061c6b94508d88f43ad3b3893ca213506 57758911253f6b31df2a87c10eb08a2c9b8450768cb8dd0d378d93f7c2e220f0
```
Or with the more detailed json output:
``` console
cardano-signer sign --cip8 \
	--address "stake_test1uqt3nqapz799tvp2lt8adttt29k6xa2xnltahn655tu4sgc6asaqg" \
	--data '{"choice":"Yes","comment":"","network":"preview","proposal":"2038c417d112e005ef61c95d710ee62184a6c177d18b2da891f97cefae4f8535","protocol":"SundaeSwap","title":"Test Proposal - Tampered","version":"1","votedAt":"3137227","voter":"stake_test1uqt3nqapz799tvp2lt8adttt29k6xa2xnltahn655tu4sgc6asaqg"}' \
	--secret-key myStakeKey.skey \
	--testnet-magic 1 \
	--json-extended
```
``` json
{
  "workMode": "sign-cip8",
  "addressHex": "e0171983a1178a55b02afacfd6ad6b516da375469fd7dbcf54a2f95823",
  "inputDataHex": "7b2263686f696365223a22596573222c22636f6d6d656e74223a22222c226e6574776f726b223a2270726576696577222c2270726f706f73616c223a2232303338633431376431313265303035656636316339356437313065653632313834613663313737643138623264613839316639376365666165346638353335222c2270726f746f636f6c223a2253756e64616553776170222c227469746c65223a22546573742050726f706f73616c202d2054616d7065726564222c2276657273696f6e223a2231222c22766f7465644174223a2233313337323237222c22766f746572223a227374616b655f7465737431757174336e7161707a373939747670326c7438616474747432396b36786132786e6c7461686e363535747534736763366173617167227d",
  "signDataHex": "846a5369676e617475726531582aa201276761646472657373581de0171983a1178a55b02afacfd6ad6b516da375469fd7dbcf54a2f95823405901277b2263686f696365223a22596573222c22636f6d6d656e74223a22222c226e6574776f726b223a2270726576696577222c2270726f706f73616c223a2232303338633431376431313265303035656636316339356437313065653632313834613663313737643138623264613839316639376365666165346638353335222c2270726f746f636f6c223a2253756e64616553776170222c227469746c65223a22546573742050726f706f73616c202d2054616d7065726564222c2276657273696f6e223a2231222c22766f7465644174223a2233313337323237222c22766f746572223a227374616b655f7465737431757174336e7161707a373939747670326c7438616474747432396b36786132786e6c7461686e363535747534736763366173617167227d",
  "signature": "5b2e7ac3fbe3cec1540f98fcc29c1ab63778e14a653a2328b2e56af6fd2a714540708e5f3e19670b9b867151c7dfb75061c6b94508d88f43ad3b3893ca213506",
  "secretKey": "e8ddb1cfc09e163915e6c28fcb5fbb563bfef57201857e15288b67abbd91e4441e5fa179a8f90da1684ba5aa310da521651d2ce20443f149f8ca9e333a96dabc",
  "publicKey": "57758911253f6b31df2a87c10eb08a2c9b8450768cb8dd0d378d93f7c2e220f0"
}
```

<br>

### Sign hex-data payload
``` console
cardano-signer sign --cip8 \
      --address "stake_test1uqt3nqapz799tvp2lt8adttt29k6xa2xnltahn655tu4sgc6asaqg" \
      --data-hex "7b2263686f696365223a22596573222c22636f6d6d656e74223a22222c226e6574776f726b223a2270726576696577222c2270726f706f73616c223a2232303338633431376431313265303035656636316339356437313065653632313834613663313737643138623264613839316639376365666165346638353335222c2270726f746f636f6c223a2253756e64616553776170222c227469746c65223a22546573742050726f706f73616c202d2054616d7065726564222c2276657273696f6e223a2231222c22766f7465644174223a2233313337323237222c22766f746572223a227374616b655f7465737431757174336e7161707a373939747670326c7438616474747432396b36786132786e6c7461686e363535747534736763366173617167227d" \
      --secret-key myStakeKey.skey \
      --testnet-magic 1
```
Output - Signature & publicKey (hex) :
```
5b2e7ac3fbe3cec1540f98fcc29c1ab63778e14a653a2328b2e56af6fd2a714540708e5f3e19670b9b867151c7dfb75061c6b94508d88f43ad3b3893ca213506 57758911253f6b31df2a87c10eb08a2c9b8450768cb8dd0d378d93f7c2e220f0
```

<br>

## Examples - Signing in CIP-36 mode (Catalyst Voting Registration / VotingPower Delegation)

### Register/Delegate to a single voting-key with minimal parameters (Mainnet example)
``` console
cardano-signer sign --cip36 \
	--rewards-address "addr1v9ux8dwy800s5pnq327g9uzh8f2fw98ldytxqaxumh3e8kqumfr6d" \
	--vote-public-key test.voting.vkey \
	--secret-key myStakeKey.skey \
	--json
```
The output in json format (Nonce automatically calculated from current machine time):
``` json
{
  "61284": {
    "1": [
      [ "0x423fa841abf9f7fa8dfa10dacdb6737b27fdb0d9bcd9b95d48cabb53047ab769", 1 ]
    ],
    "2": "0x9be513df12b3fabe7c1b8c3f9fab0968eb2168d5689bf981c2f7c35b11718b27",
    "3": "0x617863b5c43bdf0a06608abc82f0573a549714ff69166074dcdde393d8",
    "4": 76763961,
    "5": 0
  },
  "61285": {
    "1": "0x9b3534eeedaea8300bad568be60363b9e2e829ab4249b0ba23f78738a7f952e84afd22a97b744a541c431cf8e9e0bb4a6f7431a2f752fa450b761bc0fa100b0a"
  }
}
```
If you write out the output to a file via the `--out-file` or `--out-cbor` parameter, you can directly attach it to a transaction as metadata to execute the registration/delegation on chain.
``` console
cardano-signer sign --cip36 \
	--rewards-address "addr1v9ux8dwy800s5pnq327g9uzh8f2fw98ldytxqaxumh3e8kqumfr6d" \
	--vote-public-key test.voting.vkey \
	--secret-key myStakeKey.skey \
	--out-cbor myRegistration.cbor
	
#Sending example via the SPO-Scripts like:
01_sendLovelaces.sh wallet wallet min myRegistration.cbor
```

<br>

### Register/Delegate to a single voting-key with more parameters

``` console
cardano-signer sign --cip36 \
      --rewards-address "addr_test1qrlvt2gzuvrhq7m2k00rsyzfrrqwx085cdqgum7w5nc2rxwpxkp2ajdyflxxmxztuqpu2pvvvc8p6tl3xu8a3dym5uls50mr97" \
      --secret-key ../owner.staking.skey \
      --vote-public-key somevote.vkey \
      --nonce 71948552 \
      --testnet-magic 1 \
      --out-cbor catalyst-delegation.cbor
```
Output (cbor-hex):
```
a219ef64a50181825820423fa841abf9f7fa8dfa10dacdb6737b27fdb0d9bcd9b95d48cabb53047ab769010258209be513df12b3fabe7c1b8c3f9fab0968eb2168d5689bf981c2f7c35b11718b2703583900fec5a902e307707b6ab3de38104918c0e33cf4c3408e6fcea4f0a199c13582aec9a44fcc6d984be003c5058c660e1d2ff1370fd8b49ba73f041a0449d908050019ef65a101584000780582b60c651fa9d2cd3a8cb378561520e3c76ea398f1eb8f17b25084836488d1d75cf323a4b1fa7317099c2c87e411e8403a9f71349042b5723c7fbec807
```

<br>

### Register/Delegate to multiple voting-keys with votingpower 10%,20%,70%

``` console
cardano-signer sign --cip36 \
      --rewards-address "addr_test1qrlvt2gzuvrhq7m2k00rsyzfrrqwx085cdqgum7w5nc2rxwpxkp2ajdyflxxmxztuqpu2pvvvc8p6tl3xu8a3dym5uls50mr97" \
      --secret-key ../owner.staking.skey \
      --vote-public-key ../somevote.vkey \
      --vote-weight 10 \
      --vote-public-key "C2CD50D8A231FBC1444D65ABAB4F6BF74178E6DE64722558EEEF0B73DE293A8A" \
      --vote-weight 20 \
      --vote-public-key "ed25519_pk128c305nw9xh20kearuhcwj447kzlvxdfttkk6uwnrf6qfjm9276svd678w" \
      --vote-weight 70 \
      --nonce 71948552 \
      --testnet-magic 1 \
      --out-cbor catalyst-multidelegation.cbor
```      
Output (cbor-hex):
```
a219ef64a50183825820423fa841abf9f7fa8dfa10dacdb6737b27fdb0d9bcd9b95d48cabb53047ab7690a825820c2cd50d8a231fbc1444d65abab4f6bf74178e6de64722558eeef0b73de293a8a1482582051f117d26e29aea7db3d1f2f874ab5f585f619a95aed6d71d31a7404cb6557b518460258209be513df12b3fabe7c1b8c3f9fab0968eb2168d5689bf981c2f7c35b11718b2703583900fec5a902e307707b6ab3de38104918c0e33cf4c3408e6fcea4f0a199c13582aec9a44fcc6d984be003c5058c660e1d2ff1370fd8b49ba73f041a0449d908050019ef65a101584086600d0ebbf1e0f200fc9cc148464bcb2e55b893838d0f50b208148cf9d498523dd548423b25897e6e4ce9daa19a74766704a2581cea9441d92c9e25ea901208
```
Or with two voting-keys and votingpower 1 & 5 with a json-extended output
``` console
cardano-signer sign --cip36 \
	--rewards-address "addr_test1qrlvt2gzuvrhq7m2k00rsyzfrrqwx085cdqgum7w5nc2rxwpxkp2ajdyflxxmxztuqpu2pvvvc8p6tl3xu8a3dym5uls50mr97" \
	--secret-key "f5beaeff7932a4164d270afde7716067582412e8977e67986cd9b456fc082e3a" \
	--vote-public-key ../myvote.voting.pkey --vote-weight 1 \
	--vote-public-key vote-test.vkey --vote-weight 5 \
	--nonce 123456789 \
	--testnet-magic 1 \
	--json-extended
```
The output is a more detailed json format, it contains the raw cbor output in the `.output.cbor` key, and the human-readable format in the `.output.json` key:
``` json
{
  "workMode": "sign-cip36",
  "votePurpose": "Catalyst",
  "totalVoteWeight": 6,
  "signDataHex": "7b9240ba5d45b752ed3b86767ddbcefe5da612018c8068af4d3431f3fb28e19b",
  "signature": "1f49a1074fbe01ef4f5f457a806c0595a6b232845c88ad31889d65cbd8d5160fc950cb09fb7043ff47005822920cc16fb966c6a73e7eab2876b20b48fcb38b0c",
  "secretKey": "f5beaeff7932a4164d270afde7716067582412e8977e67986cd9b456fc082e3a",
  "publicKey": "86870efc99c453a873a16492ce87738ec79a0ebd064379a62e2c9cf4e119219e",
  "output": {
    "cbor": "a219ef64a50182825820423fa841abf9f7fa8dfa10dacdb6737b27fdb0d9bcd9b95d48cabb53047ab7690182582051f117d26e29aea7db3d1f2f874ab5f585f619a95aed6d71d31a7404cb6557b50502582086870efc99c453a873a16492ce87738ec79a0ebd064379a62e2c9cf4e119219e03583900fec5a902e307707b6ab3de38104918c0e33cf4c3408e6fcea4f0a199c13582aec9a44fcc6d984be003c5058c660e1d2ff1370fd8b49ba73f041a075bcd15050019ef65a10158401f49a1074fbe01ef4f5f457a806c0595a6b232845c88ad31889d65cbd8d5160fc950cb09fb7043ff47005822920cc16fb966c6a73e7eab2876b20b48fcb38b0c",
    "json": {
      "61284": {
        "1": [
          [
            "0x423fa841abf9f7fa8dfa10dacdb6737b27fdb0d9bcd9b95d48cabb53047ab769",
            1
          ],
          [
            "0x51f117d26e29aea7db3d1f2f874ab5f585f619a95aed6d71d31a7404cb6557b5",
            5
          ]
        ],
        "2": "0x86870efc99c453a873a16492ce87738ec79a0ebd064379a62e2c9cf4e119219e",
        "3": "0x00fec5a902e307707b6ab3de38104918c0e33cf4c3408e6fcea4f0a199c13582aec9a44fcc6d984be003c5058c660e1d2ff1370fd8b49ba73f",
        "4": 123456789,
        "5": 0
      },
      "61285": {
        "1": "0x1f49a1074fbe01ef4f5f457a806c0595a6b232845c88ad31889d65cbd8d5160fc950cb09fb7043ff47005822920cc16fb966c6a73e7eab2876b20b48fcb38b0c"
      }
    }
  }
}
```

<br>

### Deregistration from the voting-chain with minimal parameters (Mainnet example)

You can generate a deregistration metadata by using the `--deregister` flag. In that case no vote-key (vote-public-key) or rewards-address is needed as input. Just the secret-key and optionally a nonce and voting-chain-id.

``` console
cardano-signer sign --cip36 \
	--deregister \
	--secret-key myStakeKey.skey \
	--json
```
The output is a human-readable json format, if you redirect it to a file via the `--out-file` parameter, you can directly use it as metadata in a transaction on the chain. Nonce (if not provided) its automatically calculated from current machine time.
``` json
{
  "61286": {
    "1": "0x57758911253f6b31df2a87c10eb08a2c9b8450768cb8dd0d378d93f7c2e220f0",
    "2": 74858300,
    "3": 0
  },
  "61285": {
    "1": "0xc7bec561f2b80766f78c169ccb231865048e0ed7e9fb4f98f263d00e3e4a2e6126a18f70b303be63f8e01f46dd116be5c387495a7cec707d3ebc3e6be4d87008"
  }
}
```

<br>

## Examples - Verification 

### Verify text-data with a given signature and a key-file (.skey)
``` console
cardano-signer verify --data "this is a test payload :-)" \
		      --public-key test.vkey \
		      --signature "8a5fd6602094407b7e5923aa0f2694f8cb5cf39f317a61059fdc572e24fc1c7660d23c04d46355aed78b5ec35ae8cad1433e7367bb874390dfe46ed155727a08"
```
The output is plaintext (without any flag) and will be simply `true` if there is a match, or `false` if there is a mismatch. Cardano-signer also exits with an exitcode=0 (no error) in case of a match, or with exitcode=1 in case any error or mismatch occured.
```
true
```
You can generate a json output via the `--json` flag too.
``` console
cardano-signer verify --data "this is a test payload :-)" \
		      --public-key test.vkey \
		      --signature "8a5fd6602094407b7e5923aa0f2694f8cb5cf39f317a61059fdc572e24fc1c7660d23c04d46355aed78b5ec35ae8cad1433e7367bb874390dfe46ed155727a08" \
		      --json
```
``` json
{
  "result": "true"
}
```
Or a more detailed json output via the `--json-extended` flag.
``` console
cardano-signer verify --data "this is a test payload :-)" \
		      --public-key test.vkey \
		      --signature "8a5fd6602094407b7e5923aa0f2694f8cb5cf39f317a61059fdc572e24fc1c7660d23c04d46355aed78b5ec35ae8cad1433e7367bb874390dfe46ed155727a08" \
		      --json-extended
```
``` json
{
  "workMode": "verify",
  "result": "true",
  "verifyDataHex": "7468697320697320612074657374207061796c6f6164203a2d29",
  "signature": "8a5fd6602094407b7e5923aa0f2694f8cb5cf39f317a61059fdc572e24fc1c7660d23c04d46355aed78b5ec35ae8cad1433e7367bb874390dfe46ed155727a08",
  "publicKey": "57758911253f6b31df2a87c10eb08a2c9b8450768cb8dd0d378d93f7c2e220f0"
}
```
You can also do an optional address check, if the address belongs to the provided public key by adding the address with parameter `--address`:
``` console
cardano-signer verify --data "this is a test payload :-)" \
		      --public-key test.vkey \
		      --signature "8a5fd6602094407b7e5923aa0f2694f8cb5cf39f317a61059fdc572e24fc1c7660d23c04d46355aed78b5ec35ae8cad1433e7367bb874390dfe46ed155727a08" \
		      --address "addr1v9ux8dwy800s5pnq327g9uzh8f2fw98ldytxqaxumh3e8kqumfr6d"
```
```
Error: The address 'addr1v9ux8dwy800s5pnq327g9uzh8f2fw98ldytxqaxumh3e8kqumfr6d' does not belong to the provided public key.
```
And if the address matched, cardano-signer will just generate a normal output. If you have set it to `--json-extended` it also includes the address like:
``` json
{
  "workMode": "verify",
  "result": "true",
  "verifyDataHex": "7468697320697320612074657374207061796c6f6164203a2d29",
  "address": "addr1v9ux8dwy800s5pnq327g9uzh8f2fw98ldytxqaxumh3e8kqumfr6d",
  "signature": "8a5fd6602094407b7e5923aa0f2694f8cb5cf39f317a61059fdc572e24fc1c7660d23c04d46355aed78b5ec35ae8cad1433e7367bb874390dfe46ed155727a08",
  "publicKey": "57758911253f6b31df2a87c10eb08a2c9b8450768cb8dd0d378d93f7c2e220f0"
}
```


<br>

### Verify hex-data with a given signature and a key-hexstring
``` console
cardano-signer verify \
      --data-hex "8f21b675423a65244483506122492f5720d7bd35d70616348089678ed4eb07a9" \
      --signature "ca3ddc10f845dbe0c22875aaf91f66323d3f28e265696dcd3c56b91a8e675c9e30fd86ba69b9d1cf271a12f7710c9f3385c78cbf016e17e1df339bea8bd2db03" \
      --public-key "9be513df12b3fabe7c1b8c3f9fab0968eb2168d5689bf981c2f7c35b11718b27"
```
The output is plaintext and will be simply `true` if there is a match, or `false` if there is a mismatch. Cardano-signer also exits with an exitcode=0 (no error) in case of a match, or with exitcode=1 in case any error or mismatch occured.
```
true
```
``` console
cardano-signer verify \
      --data-hex "8f21b675423a65244483506122492f5720d7bd35d70616348089678ed4eb07a9" \
      --signature "ca3ddc10f845dbe0c22875aaf91f66323d3f28e265696dcd3c56b91a8e675c9e30fd86ba69b9d1cf271a12f7710c9f3385c78cbf016e17e1df339bea8bd2db03" \
      --public-key "aaaaaaaaaab3fabe7c1b8c3f9fab0968eb2168d5689bf981c2f7c35b11718b27"
```
```
false
```
``` console
cardano-signer verify \
      --data-hex "8f21b675423a65244483506122492f5720d7bd35d70616348089678ed4eb07a9" \
      --signature "aaaaaaaaaa45dbe0c22875aaf91f66323d3f28e265696dcd3c56b91a8e675c9e30fd86ba69b9d1cf271a12f7710c9f3385c78cbf016e17e1df339bea8bd2db03" \
      --public-key "9be513df12b3fabe7c1b8c3f9fab0968eb2168d5689bf981c2f7c35b11718b27" \
      --json
```
``` json
{
  "result": "false"
}
```

<br>

### Verify hex-data with a signature and a key-file
``` console
cardano-signer verify \
      --data-hex "8f21b675423a65244483506122492f5720d7bd35d70616348089678ed4eb07a9" \
      --signature "ca3ddc10f845dbe0c22875aaf91f66323d3f28e265696dcd3c56b91a8e675c9e30fd86ba69b9d1cf271a12f7710c9f3385c78cbf016e17e1df339bea8bd2db03" \
      --public-key owner.staking.vkey
```
```
true
```
``` console
cardano-signer verify \
      --data-hex "8f21b675423a65244483506122492f5720d7bd35d70616348089678ed4eb07a9" \
      --signature "ca3ddc10f845dbe0c22875aaf91f66323d3f28e265696dcd3c56b91a8e675c9e30fd86ba69b9d1cf271a12f7710c9f3385c78cbf016e17e1df339bea8bd2db03" \
      --public-key owner.staking.skey
```
You will also get errors if the provided key is not a public-key for example
```
Error: The file 'owner.staking.skey' is not a verification/public key json
```

<br>

### Verify a file with a signature and a key-file
``` console
cardano-signer verify --data-file test.txt --public-key test.vkey \
                      --signature "caacb18c46319f55b932efa77357f14b66b27aa908750df2c91800dc59711015ea2e568974ac0bcabf9b1c4708b877c2b94a7658c2dcad78b108049062572e09"
```
```
true
```

<br>
<br>

## Release Notes / Change-Logs

* **1.10.1**
  #### CIP-36 updates:
     - Starting with Fund10, the rewards address for the voting rewards must be a regular payment address (enterprise or base address), not a stake address like before.

* **1.10.0**
  - Added an optional address check for the normal sign/verify functions via the `--address` parameter. If provided, cardano-signer checks that the address belongs to the provided signing/public key.

* **1.9.0**
  #### CIP-36 mode updates:
    - Added the new [deregistration metadata format](https://github.com/cardano-foundation/CIPs/tree/master/CIP-0036#deregistration-metadata-format-catalyst) in CIP-36 mode, which is using key 61286 for the deregistration data.
    - Changed the output of `--json-extended` in CIP-36 mode to output the cbor and json content below the "output" key [example](https://github.com/gitmachtl/cardano-signer/edit/main/README.md#signing-cip-36-mode---catalyst-voting-registration--votingpower-delegation)
  #### General:
    - Using the general bech32 lib to decode public/private keys, so **any bech32 string** can be used. Before it was limited to `ed25519_pk` and `ed25519_sk` prefixes.
    - Defining command-line argument types to avoid parsing arguments like `--data-hex="000000"` as a number. Must be parsed as a string of course.
    - Added command-line aliases so you **can also use**: `--signing-key` or `--secret-key`, `--verification-key` or `--public-key`, etc.

* **1.8.0**
  #### CIP-36 mode updates:
	- Allow duplicated voting_key entries
	- New check to avoid using a wrong vote-public-key or a wrong stake secret-key. Because the public-key of the signing secret-key must be different than the entries in the delegations array.
	- New check that the total-vote-weight is not zero
	- Added the fields `votePurpose` and `totalVoteWeight` to the `--json-extended` output-mode
	- Syntax Update: Added flag `--deregister` to generate an empty delegation array, no voting_keys or rewards address is needed using that flag
	- Syntax Update: If no `--nonce` parameter is provided, cardano-signer automatically calculates the Mainnet slotHeight from the current machine time and uses it as the nonce
  #### General:
  - Syntax Update: Added parameter `--testnet-magic [xxx]` to CIP-8 and CIP-36 mode to allow an additional check about the right bech-address format. (Default = mainnet)

* **1.7.0**
	- Added JSON and JSON-Extended output format: Default output format is plaintext, using the `--json` flag generates a JSON output. Using the `--json-extended` flag generates a JSON output with much more information.
	- In CIP-36 mode, using the new `--json` flag together with the `--out-file` parameter generates directly a JSON Format which is compatible to be used as a registration.json metadata with cardano-cli. `--out-cbor` always generates a binary registration.cbor metadata file, also compatible to be used with cardano-cli.
	- Usage/Help context is now colored for better readability

* **1.6.1**
	- Added new check in CIP-36 mode to avoid duplicated voting_key entries in the delegations. Exits with an error if duplicates are found.

* **1.6.0**
	- New Syntax - Now you can use the parameter `--data-file` to use any binary file as the data source to sign.
	- Added the function to directly use bech encoded secret and public keys for the signing/verification. You can mix the formats.

* **1.5.0**
	- New CIP-36 mode via parameter `--cip36`. This enables the new catalyst/governance registration and votingpower (multi-)delegation mode. Output generates a signed cbor file or hex_string.

* **1.4.0**
	- New CIP-8 mode via parameter `--cip8`. This enables CIP-8 conform payload signing. 
	- New Syntax - Now you can use the parameter `--data` for pure text payloads, and `--data-hex` for hex-encoded payloads. 

* **1.3.0**
	- Now supporting true parameter/flag names.
	- Added new optional `--out-file` option, which would write the signature+publicKey to a file and not to the standard output.

* **1.2.0**
	- Added support to use Cardano-Key-Files in addition to a direct Key-Hexstring. Supports standard sKey/vKey JSON files and also files with a Bech32-Key in it, like the ones generated via jcli

* **1.1.0**
	- Added functionality to do also a Verification of the Signature together with the data and the Public Key.

* **1.0.0**
	- Initial version, supports signing of a Data-Hexstring string with a Key-Hexstring.

<br>
<br>

## Contacts

* Telegram - @atada_stakepool<br>
* Twitter - [@ATADA_Stakepool](https://twitter.com/ATADA_Stakepool)<br>
* Discord - MartinLang \[ATADA, SPO Scripts\]#5306
* Email - stakepool@stakepool.at<br>
* Homepage - https://stakepool.at
