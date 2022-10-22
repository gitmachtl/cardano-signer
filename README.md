# Tool to sign data with a Cardano-Secret-Key // verify data with a Cardano-Public-Key // generate CIP-8 & CIP-36 data

<img src="https://user-images.githubusercontent.com/47434720/190806957-114b1342-7392-4256-9c5b-c65fc0068659.png" align=right width=40%></img>

### What can cardano-signer sign?
* **Sign** any hexdata, textdata or binaryfile with a provided normal or extended secret key. The key can be provided in hex, bech or file format. The signing output is a signature in hex- or json-format, also the public key of the provided secret key for verification.
* Sign payloads in **CIP-8** mode. The signing output is a signature in hex format and also the public key of the provided secret key for verification. The output can also be set to be in json format which will also show additional data (--json-extended).
* Generate and sign **Catalyst registration/delegation/deregistration** metadata in **CIP-36** mode. This also includes relatively weighted voting power delegation. The output is the registration/delegation or deregistraton data in json or cborHex-format and/or a binary cbor file, which can be transmitted on chain as it is.

### What can cardano-signer verify?
* **Verify** a signature for any hexdata, textdata or binaryfile together with a provided public key. The key can be provided in hex, bech or file format. The verification output is true(exitcode=0) or false(exitcode=1) as a console output or in json-format.

<br>
<br>

## Usage

``` console

$ ./cardano-signer help

cardano-signer 1.9.0

Signing a hex/text-string or a binary-file:

   Syntax: cardano-signer sign
   Params: --data-hex "<hex>" | --data "<text>" | --data-file "<path_to_file>"
                                                                data/payload/file to sign in hex-, text- or binary-file-format
           --secret-key "<path_to_file>|<hex>|<bech>"           path to a signing-key-file or a direct signing hex/bech-key string
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
           --rewards-address "<bech_address>"                   rewards stake address (bech format like 'stake1..., stake_test1...')
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
           [--json | --json-extended]                           optional flag to generate output in json/json-extended format
           [--out-file "<path_to_file>"]                        path to an output file, default: standard-output
   Output: "true/false" (exitcode 0/1) or JSON-Format

```

![image](https://user-images.githubusercontent.com/47434720/197326961-31b8be92-22cf-42e4-b901-9d6212e1ff32.png)

<br>
<br>

## Examples

### Signing (in defaultmode)

``` console
### SIGN HEXDATA OR TEXTDATA WITH A KEY-HEXSTRING

$ cardano-signer sign \
      --data-hex "8f21b675423a65244483506122492f5720d7bd35d70616348089678ed4eb07a9" \
      --secret-key "c14ef0cc5e352446d6243976f51e8ffb2ae257f2a547c4fba170964a76501e7a"
      
Output (cbor-hex):
ca3ddc10f845dbe0c22875aaf91f66323d3f28e265696dcd3c56b91a8e675c9e30fd86ba69b9d1cf271a12f7710c9f3385c78cbf016e17e1df339bea8bd2db03 9be513df12b3fabe7c1b8c3f9fab0968eb2168d5689bf981c2f7c35b11718b27

$ cardano-signer sign \
      --out-file mySignature.txt \
      --data-hex "8f21b675423a65244483506122492f5720d7bd35d70616348089678ed4eb07a9" \
      --secret-key "c14ef0cc5e352446d6243976f51e8ffb2ae257f2a547c4fba170964a76501e7a"
#Signature+publicKey was written to the file mySignature.txt

$ cardano-signer sign \
      --data-hex "8f21b675423a65244483506122492f5720d7bd35d70616348089678ed4eb07a9" \
      --secret-key "c14ef0cc5e352446d6243976f51e8ffb2ae257f2a547c4fba170964a"
Error: Invalid normal secret key

$ cardano-signer sign \
      --data-hex "8f21b675423a65244483506122492f5720d7bd35d70616348089678ed4eb07a9" \
      --secret-key "c14ef0cc5e352446d6243976f51e8ffb2ae257f2a547c4fba170964a76501e7a88afe88fa8f888544e6f5a5f555e5faf6f6f"
Error: Invalid extended secret key

### SIGN HEXDATA OR TEXTDATA WITH A KEY-FILE

$ cardano-signer sign \
      --data-hex "8f21b675423a65244483506122492f5720d7bd35d70616348089678ed4eb07a9" \
      --secret-key owner.staking.skey
      
Output (cbor-hex):
ca3ddc10f845dbe0c22875aaf91f66323d3f28e265696dcd3c56b91a8e675c9e30fd86ba69b9d1cf271a12f7710c9f3385c78cbf016e17e1df339bea8bd2db03 9be513df12b3fabe7c1b8c3f9fab0968eb2168d5689bf981c2f7c35b11718b27

$ cardano-signer sign \
      --data-hex "8f21b675423a65244483506122492f5720d7bd35d70616348089678ed4eb07a9" \
      --secret-key owner.staking.vkey
Error: The file 'owner.staking.vkey' is not a signing/secret key json

### SIGN A FILE WITH A KEY-FILE

$ cardano-signer sign --data-file test.txt --secret-key test.skey

Output (cbor-hex):
caacb18c46319f55b932efa77357f14b66b27aa908750df2c91800dc59711015ea2e568974ac0bcabf9b1c4708b877c2b94a7658c2dcad78b108049062572e09 57758911253f6b31df2a87c10eb08a2c9b8450768cb8dd0d378d93f7c2e220f0

```

<br>

### Signing (CIP-8 mode)

``` console
### SIGN TEXTDATA IN CIP-8 MODE

$ cardano-signer sign --cip8 \
      --address "stake_test1uqt3nqapz799tvp2lt8adttt29k6xa2xnltahn655tu4sgc6asaqg" \
      --data '{"choice":"Yes","comment":"","network":"preview","proposal":"2038c417d112e005ef61c95d710ee62184a6c177d18b2da891f97cefae4f8535","protocol":"SundaeSwap","title":"Test Proposal - Tampered","version":"1","votedAt":"3137227","voter":"stake_test1uqt3nqapz799tvp2lt8adttt29k6xa2xnltahn655tu4sgc6asaqg"}' \
      --secret-key myStakeKey.skey \
      --testnet-magic 1
      
Output (cbor-hex):
5b2e7ac3fbe3cec1540f98fcc29c1ab63778e14a653a2328b2e56af6fd2a714540708e5f3e19670b9b867151c7dfb75061c6b94508d88f43ad3b3893ca213506 57758911253f6b31df2a87c10eb08a2c9b8450768cb8dd0d378d93f7c2e220f0

$ cardano-signer sign --cip8 \
	--address "stake_test1uqt3nqapz799tvp2lt8adttt29k6xa2xnltahn655tu4sgc6asaqg" \
	--data '{"choice":"Yes","comment":"","network":"preview","proposal":"2038c417d112e005ef61c95d710ee62184a6c177d18b2da891f97cefae4f8535","protocol":"SundaeSwap","title":"Test Proposal - Tampered","version":"1","votedAt":"3137227","voter":"stake_test1uqt3nqapz799tvp2lt8adttt29k6xa2xnltahn655tu4sgc6asaqg"}' \
	--secret-key myStakeKey.skey \
	--testnet-magic 1 \
	--json-extended

Output (extended-json):
{
  "workMode": "sign-cip8",
  "addressHex": "e0171983a1178a55b02afacfd6ad6b516da375469fd7dbcf54a2f95823",
  "inputDataHex": "7b2263686f696365223a22596573222c22636f6d6d656e74223a22222c226e6574776f726b223a2270726576696577222c2270726f706f73616c223a2232303338633431376431313265303035656636316339356437313065653632313834613663313737643138623264613839316639376365666165346638353335222c2270726f746f636f6c223a2253756e64616553776170222c227469746c65223a22546573742050726f706f73616c202d2054616d7065726564222c2276657273696f6e223a2231222c22766f7465644174223a2233313337323237222c22766f746572223a227374616b655f7465737431757174336e7161707a373939747670326c7438616474747432396b36786132786e6c7461686e363535747534736763366173617167227d",
  "signDataHex": "846a5369676e617475726531582aa201276761646472657373581de0171983a1178a55b02afacfd6ad6b516da375469fd7dbcf54a2f95823405901277b2263686f696365223a22596573222c22636f6d6d656e74223a22222c226e6574776f726b223a2270726576696577222c2270726f706f73616c223a2232303338633431376431313265303035656636316339356437313065653632313834613663313737643138623264613839316639376365666165346638353335222c2270726f746f636f6c223a2253756e64616553776170222c227469746c65223a22546573742050726f706f73616c202d2054616d7065726564222c2276657273696f6e223a2231222c22766f7465644174223a2233313337323237222c22766f746572223a227374616b655f7465737431757174336e7161707a373939747670326c7438616474747432396b36786132786e6c7461686e363535747534736763366173617167227d",
  "signature": "5b2e7ac3fbe3cec1540f98fcc29c1ab63778e14a653a2328b2e56af6fd2a714540708e5f3e19670b9b867151c7dfb75061c6b94508d88f43ad3b3893ca213506",
  "secretKey": "e8ddb1cfc09e163915e6c28fcb5fbb563bfef57201857e15288b67abbd91e4441e5fa179a8f90da1684ba5aa310da521651d2ce20443f149f8ca9e333a96dabc",
  "publicKey": "57758911253f6b31df2a87c10eb08a2c9b8450768cb8dd0d378d93f7c2e220f0"
}

### SIGN HEXDATA IN CIP-8 MODE

$ cardano-signer sign --cip8 \
      --address "stake_test1uqt3nqapz799tvp2lt8adttt29k6xa2xnltahn655tu4sgc6asaqg" \
      --data-hex "7b2263686f696365223a22596573222c22636f6d6d656e74223a22222c226e6574776f726b223a2270726576696577222c2270726f706f73616c223a2232303338633431376431313265303035656636316339356437313065653632313834613663313737643138623264613839316639376365666165346638353335222c2270726f746f636f6c223a2253756e64616553776170222c227469746c65223a22546573742050726f706f73616c202d2054616d7065726564222c2276657273696f6e223a2231222c22766f7465644174223a2233313337323237222c22766f746572223a227374616b655f7465737431757174336e7161707a373939747670326c7438616474747432396b36786132786e6c7461686e363535747534736763366173617167227d" \
      --secret-key myStakeKey.skey \
      --testnet-magic 1

Output (cbor-hex):
5b2e7ac3fbe3cec1540f98fcc29c1ab63778e14a653a2328b2e56af6fd2a714540708e5f3e19670b9b867151c7dfb75061c6b94508d88f43ad3b3893ca213506 57758911253f6b31df2a87c10eb08a2c9b8450768cb8dd0d378d93f7c2e220f0
```

<br>

### Signing (CIP-36 mode) - Catalyst Voting Registration / VotingPower Delegation

``` console
### REGISTER/DELEGATE TO A SINGLE VOTING-KEY WITH MINIMAL PARAMETERS (Mainnet example)

$ cardano-signer sign --cip36 \
	--rewards-address "stake1u55c9gha99xz3dnxxeczsr3f4kj23zs4mtpst3szlztengsv62rry" \
	--vote-public-key test.voting.vkey \
	--secret-key myStakeKey.skey \
	--json

Output (json): (Nonce automatically calculated from current machine time)
{
  "61284": {
    "1": [
      [ "0xc2cd50d8a231fbc1488d65abab4f6bf74178e6de64722558eeef0b73de293a8a", 1 ]
    ],
    "2": "0x57758911253aa6b31df2a87c10eb08a2c9b8450768cb8dd0d378d93f7c2e220f0",
    "3": "0xe1e382a2fd294c28b7763670280e29ada4a88a15dac305c602f89799a2",
    "4": 73146002,
    "5": 0
  },
  "61285": {
    "1": "0x4a96002...3278ea09"
  }
}

### REGISTER/DELEGATE TO A SINGLE VOTING-KEY MORE PARAMETERS

$ cardano-signer sign --cip36 \
      --rewards-address "stake_test1urqntq4wexjylnrdnp97qq79qkxxvrsa9lcnwr7ckjd6w0cr04y4p" \
      --secret-key ../owner.staking.skey \
      --vote-public-key somevote.vkey \
      --nonce 71948552 \
      --testnet-magic 1 \
      --out-cbor catalyst-delegation.cbor

Output (cbor-hex):
a219ef64a5018182582057758911253f6b31df2a87c10eb08a2c9b8450768cb8dd0d378d93f7c2e220f0010258209be513df12b3fabe7c1b8c3f9fab0968eb2168d5689bf981c2f7c35b11718b2703581de0c13582aec9a44fcc6d984be003c5058c660e1d2ff1370fd8b49ba73f041a0449d908050019ef65a1015840c839244556db17a2df914c7291c891e5abd1bd580de7786d640da9e27983efe86495cbee900eb685c08e367e778bb0860c6e366b9ec715d8fba824ef55c8aa0f

### REGISTER/DELEGATE TO MULTIPLE VOTING-KEYS WITH VOTINGPOWER 10%,20%,70%

$ cardano-signer sign --cip36 \
      --rewards-address "stake_test1urqntq4wexjylnrdnp97qq79qkxxvrsa9lcnwr7ckjd6w0cr04y4p" \
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
      
Output (cbor-hex):
a219ef64a5018382582099d1d0c4cdc8a4b206066e9606c6c3729678bd7338a8eab9bffdffa39d3df9580a825820c2cd50d8a231fbc1444d65abab4f6bf74178e6de64722558eeef0b73de293a8a1482582051f117d26e29aea7db3d1f2f874ab5f585f619a95aed6d71d31a7404cb6557b518460258209be513df12b3fabe7c1b8c3f9fab0968eb2168d5689bf981c2f7c35b11718b2703581de0c13582aec9a44fcc6d984be003c5058c660e1d2ff1370fd8b49ba73f041a0449d908050019ef65a1015840ecce4b2e10146857b9f583ce01b10a26726022963d47fd61d0fbb67b543428fa46315d4e35b2ab73e7e15f620883176422a19e780a751d71ac488053365e6402

$ cardano-signer sign --cip36 \
	--rewards-address "stake_test1urqntq4wexjylnrdnp97qq79qkxxvrsa9lcnwr7ckjd6w0cr04y4p" \
	--secret-key "f5beaeff7932a4164d270afde7716067582412e8977e67986cd9b456fc082e3a" \
	--vote-public-key ../myvote.voting.pkey --vote-weight 1 \
	--vote-public-key vote-test.vkey --vote-weight 5 \
	--nonce 123456789 \
	--testnet-magic 1 \
	--json-extended

Output (extended-json):
{
  "workMode": "sign-cip36",
  "votePurpose": "Catalyst",
  "totalVoteWeight": 6,
  "signDataHex": "45d05fca1f25e1a01c375dc2c8896e1fe61619852bbef2b26b4ece433c5bdeb7",
  "signature": "a97affe866b515f3dadb3038b4ccc58bf689005d417300fbf57d3f17eceb553d7354d919adb59a8b6dc30afb6cdda414812c3ffd4dfceebb15e391a7415bde0d",
  "secretKey": "f5beaeff7932a4164d270afde7716067582412e8977e67986cd9b456fc082e3a",
  "publicKey": "86870efc99c453a873a16492ce87738ec79a0ebd064379a62e2c9cf4e119219e",
  "output": {
    "cbor": "a219ef64a5018282582051f117d26e29aea7db3d1f2f874ab5f585f619a95aed6d71d31a7404cb6557b50182582057758911253f6b31df2a87c10eb08a2c9b8450768cb8dd0d378d93f7c2e220f00502582086870efc99c453a873a16492ce87738ec79a0ebd064379a62e2c9cf4e119219e03581de0c13582aec9a44fcc6d984be003c5058c660e1d2ff1370fd8b49ba73f041a075bcd15050019ef65a1015840a97affe866b515f3dadb3038b4ccc58bf689005d417300fbf57d3f17eceb553d7354d919adb59a8b6dc30afb6cdda414812c3ffd4dfceebb15e391a7415bde0d",
    "json": {
      "61284": {
        "1": [
          [
            "0x51f117d26e29aea7db3d1f2f874ab5f585f619a95aed6d71d31a7404cb6557b5",
            1
          ],
          [
            "0x57758911253f6b31df2a87c10eb08a2c9b8450768cb8dd0d378d93f7c2e220f0",
            5
          ]
        ],
        "2": "0x86870efc99c453a873a16492ce87738ec79a0ebd064379a62e2c9cf4e119219e",
        "3": "0xe0c13582aec9a44fcc6d984be003c5058c660e1d2ff1370fd8b49ba73f",
        "4": 123456789,
        "5": 0
      },
      "61285": {
        "1": "0xa97affe866b515f3dadb3038b4ccc58bf689005d417300fbf57d3f17eceb553d7354d919adb59a8b6dc30afb6cdda414812c3ffd4dfceebb15e391a7415bde0d"
      }
    }
  }
}
```

### Signing (CIP-36 mode) - Catalyst Voting-Chain De-Registration

``` console
### DEREGISTER FROM THE VOTING-CHAIN WITH MINIMAL PARAMETERS (Mainnet example)

$ cardano-signer sign --cip36 \
	--deregister \
	--secret-key myStakeKey.skey \
	--json

Output (json): (Nonce automatically calculated from current machine time)
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

### Verification 

``` console
### VERIFY HEXDATA or TEXTDATA WITH A SIGNATURE AND A KEY-HEXSTRING

$ cardano-signer verify \
      --data-hex "8f21b675423a65244483506122492f5720d7bd35d70616348089678ed4eb07a9" \
      --signature "ca3ddc10f845dbe0c22875aaf91f66323d3f28e265696dcd3c56b91a8e675c9e30fd86ba69b9d1cf271a12f7710c9f3385c78cbf016e17e1df339bea8bd2db03" \
      --public-key "9be513df12b3fabe7c1b8c3f9fab0968eb2168d5689bf981c2f7c35b11718b27"

true

$ cardano-signer verify \
      --data-hex "8f21b675423a65244483506122492f5720d7bd35d70616348089678ed4eb07a9" \
      --signature "ca3ddc10f845dbe0c22875aaf91f66323d3f28e265696dcd3c56b91a8e675c9e30fd86ba69b9d1cf271a12f7710c9f3385c78cbf016e17e1df339bea8bd2db03" \
      --public-key "aaaaaaaaaab3fabe7c1b8c3f9fab0968eb2168d5689bf981c2f7c35b11718b27"

false

$ cardano-signer verify \
      --data-hex "8f21b675423a65244483506122492f5720d7bd35d70616348089678ed4eb07a9" \
      --signature "aaaaaaaaaa45dbe0c22875aaf91f66323d3f28e265696dcd3c56b91a8e675c9e30fd86ba69b9d1cf271a12f7710c9f3385c78cbf016e17e1df339bea8bd2db03" \
      --public-key "9be513df12b3fabe7c1b8c3f9fab0968eb2168d5689bf981c2f7c35b11718b27"

false

### VERIFY HEXDATA WITH A SIGNATURE AND A KEY-FILE

$ cardano-signer verify \
      --data-hex "8f21b675423a65244483506122492f5720d7bd35d70616348089678ed4eb07a9" \
      --signature "ca3ddc10f845dbe0c22875aaf91f66323d3f28e265696dcd3c56b91a8e675c9e30fd86ba69b9d1cf271a12f7710c9f3385c78cbf016e17e1df339bea8bd2db03" \
      --public-key owner.staking.vkey

true

$ cardano-signer verify \
      --data-hex "8f21b675423a65244483506122492f5720d7bd35d70616348089678ed4eb07a9" \
      --signature "ca3ddc10f845dbe0c22875aaf91f66323d3f28e265696dcd3c56b91a8e675c9e30fd86ba69b9d1cf271a12f7710c9f3385c78cbf016e17e1df339bea8bd2db03" \
      --public-key owner.staking.skey
Error: The file 'owner.staking.skey' is not a verification/public key json

### VERIFY A FILE WITH A SIGNATURE AND A KEY-FILE

$ cardano-signer verify --data-file test.txt --public-key test.vkey --signature "caacb18c46319f55b932efa77357f14b66b27aa908750df2c91800dc59711015ea2e568974ac0bcabf9b1c4708b877c2b94a7658c2dcad78b108049062572e09"

true
```

<br>
<br>

## Release Notes / Change-Logs

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
