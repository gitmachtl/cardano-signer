# Sign & verify data with a Cardano Secret/Public-Key<br>Sign & verify CIP-8, CIP-30 & CIP-36 data (Catalyst)<br>Generate Cardano-Keys from Mnemonics and Derivation-Paths

<img src="https://user-images.githubusercontent.com/47434720/190806957-114b1342-7392-4256-9c5b-c65fc0068659.png" align=right width=40%></img>

&nbsp;<p>

### What can cardano-signer sign/generate?
* **Sign** any hexdata, textdata or binaryfile with a provided normal or extended secret key. The key can be provided in hex, bech or file format. The signing output is a signature in hex- or json-format, also the public key of the provided secret key for verification. With the enabled `--jcli` flag the generated signature and public key will be return in a **jcli** compatible bech format. **Cardano-signer can be used instead of jcli for signing**.
* Sign payloads in **CIP-8 / CIP-30** mode, hashed or not hashed, with or without a payload in the output. The signing output is a COSE_Sign1 signature in hex format and also the public key of the provided secret key for verification. The output can also be set to be in json format which will also show additional data (--json-extended).
* Generate and sign **Catalyst registration/delegation/deregistration** metadata in **CIP-36** mode. This also includes relatively weighted voting power delegation. The output is the registration/delegation or deregistraton data in json or cborHex-format and/or a binary cbor file, which can be transmitted on chain as it is.
* Generate **Cardano Keys** like .skey/.vkey files and hex-keys from **derivation paths**, with or without **mnemonic words**.
* Generate conway **dRep Keys** with or without **mnemonic words**.
* Generate CIP36 voting-keys.
* A given address will automatically be checked against the used publicKey.

### What can cardano-signer verify?
* **Verify** a signature for any hexdata, textdata or binaryfile together with a provided public key. Also an optional address can be verified against the given public key. The key can be provided in hex, bech or file format. The verification output is true(exitcode=0) or false(exitcode=1) as a console output or in json-format.
* The signature can be provided in hex format or also in bech encoded `ed25519_sig` format. **Cardano-signer can be used instead of jcli for verification**.
* Verify **CIP-8 / CIP-30** COSE_Sign1/COSE_Key data. With hashed or non-hashed payloads. There is also a detailed check on the COSE_Sign1 and COSE_Key data structure included. Verification can be done on the COSE_Sign1 + COSE_Key, or COSE_Sign1 + COSE_Key + payload and/or address.

&nbsp;<p>

## Examples
* **[Default mode](#default-mode)**: Sign and verify data with ed25519(cardano) keys
* **[CIP-8 / CIP-30 mode](#cip-8--cip-30-mode)**: COSE_Sign1 signature & COSE_Key publicKey generation/verification
* **[CIP-36 mode](#cip-36-mode-catalyst-voting-registration--votingpower-delegation)**: Generate Catalyst metadata for registration/delegation and also deregistration
* **[KeyGeneration mode](#keygeneration-mode)**: Generate Cardano keys from mnemonics and derivation-paths
&nbsp;<p>

## Full syntax

``` console

$ ./cardano-signer help

cardano-signer 1.13.0

Sign a hex/text-string or a binary-file:

   Syntax: cardano-signer sign
   Params: --data-hex "<hex>" | --data "<text>" | --data-file "<path_to_file>"
                                                                data/payload/file to sign in hex-, text- or binary-file-format
           --secret-key "<path_to_file>|<hex>|<bech>"           path to a signing-key-file or a direct signing hex/bech-key string
           [--address "<path_to_file>|<hex>|<bech>"]            optional address check against the signing-key (address-file or a direct bech/hex format)
           [--json | --json-extended]                           optional flag to generate output in json/json-extended format
           [--jcli | --bech]                                    optional flag to generate signature & publicKey in jcli compatible bech-format
           [--out-file "<path_to_file>"]                        path to an output file, default: standard-output
   Output: "signature + publicKey" or JSON-Format               default: hex-format


Sign a payload in CIP-8 / CIP-30 mode: (COSE_Sign1 only currently)

   Syntax: cardano-signer sign --cip8
           cardano-signer sign --cip30
   Params: --data-hex "<hex>" | --data "<text>" | --data-file "<path_to_file>"
                                                                data/payload/file to sign in hex-, text- or binary-file-format
           --secret-key "<path_to_file>|<hex>|<bech>"           path to a signing-key-file or a direct signing hex/bech-key string
           --address "<path_to_file>|<hex>|<bech>"              path to an address-file or a direct bech/hex format 'stake1..., stake_test1..., addr1...'
           [--hashed]                                           optional flag to hash the payload given via the 'data' parameters
           [--nopayload]                                        optional flag to exclude the payload from the COSE_Sign1 signature, default: included
           [--testnet-magic [xxx]]                              optional flag to switch the address check to testnet-addresses, default: mainnet
           [--json | --json-extended]                           optional flag to generate output in json/json-extended format
           [--out-file "<path_to_file>"]                        path to an output file, default: standard-output
   Output: "COSE_Sign1 + COSE_Key" or JSON-Format


Sign a catalyst registration/delegation or deregistration in CIP-36 mode:

   Syntax: cardano-signer sign --cip36
   Params: [--vote-public-key "<path_to_file>|<hex>|<bech>"     public-key-file(s) or public hex/bech-key string(s) to delegate the votingpower to (single or multiple)
           --vote-weight <unsigned_int>]                        relative weight of each delegated votingpower, default: 100% for a single delegation
           --secret-key "<path_to_file>|<hex>|<bech>"           signing-key-file or a direct signing hex/bech-key string of the stake key (votingpower)
           --payment-address "<path_to_file>|<hex>|<bech>"      rewards payout address (address-file or a direct bech/hex format 'addr1..., addr_test1...')
           [--nonce <unsigned_int>]                             optional nonce value, if not provided the mainnet-slotHeight calculated from current machine-time will be used
           [--vote-purpose <unsigned_int>]                      optional parameter (unsigned int), default: 0 (catalyst)
           [--deregister]                                       optional flag to generate a deregistration (no --vote-public-key/--vote-weight/--payment-address needed
           [--testnet-magic [xxx]]                              optional flag to switch the address check to testnet-addresses, default: mainnet
           [--json | --json-extended]                           optional flag to generate output in json/json-extended format, default: cborHex(text)
           [--out-file "<path_to_file>"]                        path to an output file, default: standard-output
           [--out-cbor "<path_to_file>"]                        path to write a binary metadata.cbor file to
   Output: Registration-Metadata in JSON-, cborHex-, cborBinary-Format


Verify a hex/text-string or a binary-file via signature + publicKey:

   Syntax: cardano-signer verify
   Params: --data-hex "<hex>" | --data "<text>" | --data-file "<path_to_file>"
                                                        data/payload/file to verify in hex-, text- or binary-file-format
           --signature "<hex>|<bech>"                           signature in hex- or bech-format
           --public-key "<path_to_file>|<hex>|<bech>"           path to a public-key-file or a direct public hex/bech-key string
           [--address "<path_to_file>|<hex>|<bech>"]            optional address check against the public-key (address-file or a direct bech/hex format)
           [--json | --json-extended]                           optional flag to generate output in json/json-extended format
           [--out-file "<path_to_file>"]                        path to an output file, default: standard-output
   Output: "true/false" (exitcode 0/1) or JSON-Format


Verify a CIP-8 / CIP-30 payload: (COSE_Sign1 only currently)

   Syntax: cardano-signer verify --cip8
           cardano-signer verify --cip30
   Params: --cose-sign1 "<hex>"                                 COSE_Sign1 signature in cbor-hex-format
           --cose-key "<hex>"                                   COSE_Key containing the public-key in cbor-hex-format
           [--data-hex "<hex>" | --data "<text>" | --data-file "<path_to_file>"]
                                                                optional data/payload/file if not present in the COSE_Sign1 signature
           [--address "<path_to_file>|<hex>|<bech>"]            optional signing-address to do the verification with
           [--hashed]                                           optional flag to hash the payload given via the 'data' parameters
           [--json | --json-extended]                           optional flag to generate output in json/json-extended format
           [--out-file "<path_to_file>"]                        path to an output file, default: standard-output
   Output: "true/false" (exitcode 0/1) or JSON-Format


Generate Cardano ed25519/ed25519-extended keys:

   Syntax: cardano-signer keygen
   Params: [--path "<derivationpath>"]                          optional derivation path in the format like "1852H/1815H/0H/0/0" or "1852'/1815'/0'/0/0"
                                                                or predefined names: --path payment, --path stake, --path cip36, --path drep
           [--mnemonics "word1 word2 ... word24"]               optional mnemonic words to derive the key from (separate via space)
           [--cip36]                                            optional flag to generate CIP36 conform vote keys (also using path 1694H/1815H/0H/0/0)
           [--vote-purpose <unsigned_int>]                      optional vote-purpose (unsigned int) together with --cip36 flag, default: 0 (Catalyst)
           [--vkey-extended]                                    optional flag to generate a 64byte publicKey with chain code
           [--json | --json-extended]                           optional flag to generate output in json/json-extended format
           [--out-file "<path_to_file>"]                        path to an output file, default: standard-output
           [--out-skey "<path_to_skey_file>"]                   path to an output skey-file
           [--out-vkey "<path_to_vkey_file>"]                   path to an output vkey-file
   Output: "secretKey + publicKey" or JSON-Format               default: hex-format

```

<br>
<br>

# Default mode

## *Signing - Generate a signature*

![image](https://user-images.githubusercontent.com/47434720/208511485-34ad734d-3c0b-42f9-996a-887966cbd12d.png)

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
                    --secret-key dummy.skey \
		    --json-extended \
		    --address "addr1v9ux8dwy800s5pnq327g9uzh8f2fw98ldytxqaxumh3e8kqumfr6d"
```
If the address is wrong you will get an error like:
```
Error: The address 'addr1v9ux8dwy800s5pnq327g9uzh8f2fw98ldytxqaxumh3e8kqumfr6d' does not belong to the provided secret key.
```
If the address is correct, cardano-signer outputs like normal. In case of the **detailed json output** it also **includes the address infos**.
``` json
{
  "workMode": "sign",
  "signDataHex": "7468697320697320612074657374207061796c6f6164203a2d29",
  "addressHex": "617863b5c43bdf0a06608abc82f0573a549714ff69166074dcdde393d8",
  "addressType": "payment enterprise",
  "addressNetwork": "mainnet",
  "signature": "c60aae4701b49d0b5276b703e72b1a310d6df45b6671bcc08eb06ae9640584577d5d7bb14429bbc855a6382a40412a27f8d5c794220e26cea7404f1cfb0e5d0b",
  "secretKey": "16275bd6647f94a53e9fe1c71439a258a03c13cadf32935ed5388972ebd7e53f",
  "publicKey": "755b017578b701dc9ddd4eaee67015b4ca8baf66293b7b1d204df426c0ceccb9"
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

## *Verification*

![image](https://user-images.githubusercontent.com/47434720/208521774-acc55a42-f37d-46cd-a424-eb7dcc01f149.png)

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
		      --public-key dummy.vkey \
		      --signature "c60aae4701b49d0b5276b703e72b1a310d6df45b6671bcc08eb06ae9640584577d5d7bb14429bbc855a6382a40412a27f8d5c794220e26cea7404f1cfb0e5d0b" \
		      --address "addr1v9ux8dwy800s5pnq327g9uzh8f2fw98ldytxqaxumh3e8kqumfr6d"
```
```
Error: The address 'addr1v9ux8dwy800s5pnq327g9uzh8f2fw98ldytxqaxumh3e8kqumfr6d' does not belong to the provided public key.
```
And if the address matched, cardano-signer will just generate a normal output. If you have set it to `--json-extended` it also includes the address infos like:
``` json
{
  "workMode": "verify",
  "result": "true",
  "verifyDataHex": "7468697320697320612074657374207061796c6f6164203a2d29",
  "addressHex": "617863b5c43bdf0a06608abc82f0573a549714ff69166074dcdde393d8",
  "addressType": "payment enterprise",
  "addressNetwork": "mainnet",
  "signature": "c60aae4701b49d0b5276b703e72b1a310d6df45b6671bcc08eb06ae9640584577d5d7bb14429bbc855a6382a40412a27f8d5c794220e26cea7404f1cfb0e5d0b",
  "publicKey": "755b017578b701dc9ddd4eaee67015b4ca8baf66293b7b1d204df426c0ceccb9"
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

<p>&nbsp;<p>&nbsp;

# CIP-8 / CIP-30 mode

## *Signing - Generate the COSE_Sign1 & COSE_Key*

![image](https://user-images.githubusercontent.com/47434720/208512729-e0119b98-5d26-458f-8575-ecbb3d64241c.png)

### Sign some text-data payload

``` console
cardano-signer sign --cip8 \
	--data "Hello world" \
	--secret-key dummy.skey \
	--address dummy.addr
```
Output - **COSE_Sign1 Signature & COSE_Key publicKey** (hex):
```
84582aa201276761646472657373581d617863b5c43bdf0a06608abc82f0573a549714ff69166074dcdde393d8a166686173686564f44b48656c6c6f20776f726c645840fc58155f0cee05bc00e7299af1df1f159ac82a46a055786b259657934eff346eec81349d4678ceabc79f213c66a2bdbfd4ea5d9ebdc630bee5ac9cce75cfc001 a4010103272006215820755b017578b701dc9ddd4eaee67015b4ca8baf66293b7b1d204df426c0ceccb9
```
Or with the **more detailed** json output which includes many useful and extra information like the `signedMessage` string:
``` console
cardano-signer sign --cip8 \
	--data "Hello world" \
	--secret-key dummy.skey \
	--address dummy.addr \
	--json-extended
```
``` json
{
  "workMode": "sign-cip8",
  "addressHex": "617863b5c43bdf0a06608abc82f0573a549714ff69166074dcdde393d8",
  "addressType": "payment enterprise",
  "addressNetwork": "mainnet",
  "inputDataHex": "48656c6c6f20776f726c64",
  "isHashed": "false",
  "signDataHex": "846a5369676e617475726531582aa201276761646472657373581d617863b5c43bdf0a06608abc82f0573a549714ff69166074dcdde393d8404b48656c6c6f20776f726c64",
  "signature": "fc58155f0cee05bc00e7299af1df1f159ac82a46a055786b259657934eff346eec81349d4678ceabc79f213c66a2bdbfd4ea5d9ebdc630bee5ac9cce75cfc001",
  "secretKey": "16275bd6647f94a53e9fe1c71439a258a03c13cadf32935ed5388972ebd7e53f",
  "publicKey": "755b017578b701dc9ddd4eaee67015b4ca8baf66293b7b1d204df426c0ceccb9",
  "output": {
    "signedMessage": "cms_hFgqogEnZ2FkZHJlc3NYHWF4Y7XEO98KBmCKvILwVzpUlxT_aRZgdNzd45PYoWZoYXNoZWT0S0hlbGxvIHdvcmxkWED8WBVfDO4FvADnKZrx3x8VmsgqRqBVeGsllleTTv80buyBNJ1GeM6rx58hPGaivb_U6l2evcYwvuWsnM51z8ABZWrr1w",
    "COSE_Sign1_hex": "84582aa201276761646472657373581d617863b5c43bdf0a06608abc82f0573a549714ff69166074dcdde393d8a166686173686564f44b48656c6c6f20776f726c645840fc58155f0cee05bc00e7299af1df1f159ac82a46a055786b259657934eff346eec81349d4678ceabc79f213c66a2bdbfd4ea5d9ebdc630bee5ac9cce75cfc001",
    "COSE_Key_hex": "a4010103272006215820755b017578b701dc9ddd4eaee67015b4ca8baf66293b7b1d204df426c0ceccb9"
  }
}
```
If you wanna **hash the payload**, add the `--hashed` flag:
``` console
cardano-signer sign --cip8 \
	--data "Hello world" \
	--secret-key dummy.skey \
	--address dummy.addr \
	--hashed \
	--json-extended
```
If you wanna **exclude the payload** itself from the COSE_Sign1 output, add the `--nopayload` flag:
``` console
cardano-signer sign --cip8 \
	--data "Hello world" \
	--secret-key dummy.skey \
	--address dummy.addr \
	--nopayload \
	--json-extended
```
This will not include the payload in the COSE_Sign1 signature, useful if all involved entities know the payload.
```
COSE_Sign1 cbor:
84                                     # array(4)
   58 2a                               #   bytes(42)
      a201276761646472657373581d617863 #     "\xa2\x01\'gaddressX\x1daxc"
      b5c43bdf0a06608abc82f0573a549714 #     "\xb5\xc4;\xdf\n\x06`\x8a\xbc\x82\xf0W:T\x97\x14"
      ff69166074dcdde393d8             #     "\xffi\x16`t\xdc\xdd\xe3\x93\xd8"
   a1                                  #   map(1)
      66                               #     text(6)
         686173686564                  #       "hashed"
      f4                               #     false, simple(20)
   f6                                  #   null, simple(22)
   58 40                               #   bytes(64)
      fc58155f0cee05bc00e7299af1df1f15 #     "\xfcX\x15_\x0c\xee\x05\xbc\x00\xe7)\x9a\xf1\xdf\x1f\x15"
      9ac82a46a055786b259657934eff346e #     "\x9a\xc8*F\xa0Uxk%\x96W\x93N\xff4n"
      ec81349d4678ceabc79f213c66a2bdbf #     "\xec\x814\x9dFx\xce\xab\xc7\x9f!<f\xa2\xbd\xbf"
      d4ea5d9ebdc630bee5ac9cce75cfc001 #     "\xd4\xea]\x9e\xbd\xc60\xbe\xe5\xac\x9c\xceu\xcf\xc0\x01"
```

<br>

### Sign hex-data payload
``` console
cardano-signer sign --cip8 \
	--address "stake_test1urqntq4wexjylnrdnp97qq79qkxxvrsa9lcnwr7ckjd6w0cr04y4p" \
	--data-hex "7b2263686f696365223a22596573222c22636f6d6d656e74223a22222c226e6574776f726b223a2270726576696577222c2270726f706f73616c223a2232303338633431376431313265303035656636316339356437313065653632313834613663313737643138623264613839316639376365666165346638353335222c2270726f746f636f6c223a2253756e64616553776170222c227469746c65223a22546573742050726f706f73616c202d2054616d7065726564222c2276657273696f6e223a2231222c22766f7465644174223a2233313337323237222c22766f746572223a227374616b655f7465737431757174336e7161707a373939747670326c7438616474747432396b36786132786e6c7461686e363535747534736763366173617167227d" \
	--secret-key staking.skey \
	--testnet-magic 1 \
	--json
```
Output - **COSE_Sign1 Signature & COSE_Key publicKey** (hex):
``` json
{
  "COSE_Sign1_hex": "84582aa201276761646472657373581de0c13582aec9a44fcc6d984be003c5058c660e1d2ff1370fd8b49ba73fa166686173686564f45901277b2263686f696365223a22596573222c22636f6d6d656e74223a22222c226e6574776f726b223a2270726576696577222c2270726f706f73616c223a2232303338633431376431313265303035656636316339356437313065653632313834613663313737643138623264613839316639376365666165346638353335222c2270726f746f636f6c223a2253756e64616553776170222c227469746c65223a22546573742050726f706f73616c202d2054616d7065726564222c2276657273696f6e223a2231222c22766f7465644174223a2233313337323237222c22766f746572223a227374616b655f7465737431757174336e7161707a373939747670326c7438616474747432396b36786132786e6c7461686e363535747534736763366173617167227d5840c2ffc4650e21376297f42040028382406bf888c09f35a74324e80a531cc6359a6d2acc9a6e4c58c664463a25889de37d2f54422ae20a259db6fed37b86d05202",
  "COSE_Key_hex": "a40101032720062158209be513df12b3fabe7c1b8c3f9fab0968eb2168d5689bf981c2f7c35b11718b27"
}
```

## *Verification*

![image](https://user-images.githubusercontent.com/47434720/208522843-296257c8-fced-4573-8592-85f10b0f4762.png)

### Verify COSE_Sign1 & COSE_Key data

Lets use the signed data from the first signing example for the verification.
```
COSE_Sign1: 84582aa201276761646472657373581d617863b5c43bdf0a06608abc82f0573a549714ff69166074dcdde393d8a166686173686564f44b48656c6c6f20776f726c645840fc58155f0cee05bc00e7299af1df1f159ac82a46a055786b259657934eff346eec81349d4678ceabc79f213c66a2bdbfd4ea5d9ebdc630bee5ac9cce75cfc001
COSE_Key: a4010103272006215820755b017578b701dc9ddd4eaee67015b4ca8baf66293b7b1d204df426c0ceccb9
```
To **verify** the COSE data with a **detailed output** run:
``` console
cardano-signer verify --cip8 \
	--cose-sign1 84582aa201276761646472657373581d617863b5c43bdf0a06608abc82f0573a549714ff69166074dcdde393d8a166686173686564f44b48656c6c6f20776f726c645840fc58155f0cee05bc00e7299af1df1f159ac82a46a055786b259657934eff346eec81349d4678ceabc79f213c66a2bdbfd4ea5d9ebdc630bee5ac9cce75cfc001 \
	--cose-key a4010103272006215820755b017578b701dc9ddd4eaee67015b4ca8baf66293b7b1d204df426c0ceccb9 \
	--json-extended
```
This outputs the detailed json:
``` json
{
  "workMode": "verify-cip8",
  "result": "true",
  "addressHex": "617863b5c43bdf0a06608abc82f0573a549714ff69166074dcdde393d8",
  "addressType": "payment enterprise",
  "addressNetwork": "mainnet",
  "payloadDataHex": "48656c6c6f20776f726c64",
  "isHashed": "false",
  "verifyDataHex": "846a5369676e617475726531582aa201276761646472657373581d617863b5c43bdf0a06608abc82f0573a549714ff69166074dcdde393d8404b48656c6c6f20776f726c64",
  "signature": "fc58155f0cee05bc00e7299af1df1f159ac82a46a055786b259657934eff346eec81349d4678ceabc79f213c66a2bdbfd4ea5d9ebdc630bee5ac9cce75cfc001",
  "publicKey": "755b017578b701dc9ddd4eaee67015b4ca8baf66293b7b1d204df426c0ceccb9"
}
```
You see that the verification was successful, the used signing-address, and payload was not hashed.

### Verify COSE_Sign1 & COSE_Key data with a given payload

If you wanna verify the COSE data against a given payload, simply add it as a --data parameter:
``` console
cardano-signer verify --cip8 \
	--cose-sign1 84582aa201276761646472657373581d617863b5c43bdf0a06608abc82f0573a549714ff69166074dcdde393d8a166686173686564f44b48656c6c6f20776f726c645840fc58155f0cee05bc00e7299af1df1f159ac82a46a055786b259657934eff346eec81349d4678ceabc79f213c66a2bdbfd4ea5d9ebdc630bee5ac9cce75cfc001 \
	--cose-key a4010103272006215820755b017578b701dc9ddd4eaee67015b4ca8baf66293b7b1d204df426c0ceccb9 \
	--data 'Not hello world' \
	--json
```
``` json
{
  "result": "false"
}
```

### Verify a 'payloadless' COSE_Sign1 & COSE_Key by providing the needed payload data

If you have a COSE_Sign1 without an included payload (like the signing example further above), you need to provide the payload data to do a successful verification. In the example the payload was 'Hello world' but was not included in the COSE_Sign1, so we add it.
``` console
cardano-signer verify --cip30 \
	--cose-sign1 84582aa201276761646472657373581d617863b5c43bdf0a06608abc82f0573a549714ff69166074dcdde393d8a166686173686564f4f65840fc58155f0cee05bc00e7299af1df1f159ac82a46a055786b259657934eff346eec81349d4678ceabc79f213c66a2bdbfd4ea5d9ebdc630bee5ac9cce75cfc001 \
	--cose-key a4010103272006215820755b017578b701dc9ddd4eaee67015b4ca8baf66293b7b1d204df426c0ceccb9 \
	--data 'Hello world' \
	--json-extended
```
``` json
{
  "workMode": "verify-cip30",
  "result": "true",
  "addressHex": "617863b5c43bdf0a06608abc82f0573a549714ff69166074dcdde393d8",
  "addressType": "payment enterprise",
  "addressNetwork": "mainnet",
  "payloadDataHex": "48656c6c6f20776f726c64",
  "isHashed": "false",
  "verifyDataHex": "846a5369676e617475726531582aa201276761646472657373581d617863b5c43bdf0a06608abc82f0573a549714ff69166074dcdde393d8404b48656c6c6f20776f726c64",
  "signature": "fc58155f0cee05bc00e7299af1df1f159ac82a46a055786b259657934eff346eec81349d4678ceabc79f213c66a2bdbfd4ea5d9ebdc630bee5ac9cce75cfc001",
  "publicKey": "755b017578b701dc9ddd4eaee67015b4ca8baf66293b7b1d204df426c0ceccb9"
}
```
The verification is successful.

### Verify the address in the COSE_Sign1 & COSE_Key data

To verify the address in the COSE data simply add the address via the `--address` parameter:
``` console
cardano-signer verify --cip8 \
	--cose-sign1 84582aa201276761646472657373581d617863b5c43bdf0a06608abc82f0573a549714ff69166074dcdde393d8a166686173686564f44b48656c6c6f20776f726c645840fc58155f0cee05bc00e7299af1df1f159ac82a46a055786b259657934eff346eec81349d4678ceabc79f213c66a2bdbfd4ea5d9ebdc630bee5ac9cce75cfc001 \
	--cose-key a4010103272006215820755b017578b701dc9ddd4eaee67015b4ca8baf66293b7b1d204df426c0ceccb9 \
	--address dummy.addr
	--json
```
``` json
{
  "result": "true"
}
```
If the address does not belong to the publicKey in the COSE_Key, there will be an error.
``` console
cardano-signer verify --cip8 \
	--cose-sign1 84582aa201276761646472657373581d617863b5c43bdf0a06608abc82f0573a549714ff69166074dcdde393d8a166686173686564f44b48656c6c6f20776f726c645840fc58155f0cee05bc00e7299af1df1f159ac82a46a055786b259657934eff346eec81349d4678ceabc79f213c66a2bdbfd4ea5d9ebdc630bee5ac9cce75cfc001 \
	--cose-key a4010103272006215820755b017578b701dc9ddd4eaee67015b4ca8baf66293b7b1d204df426c0ceccb9 \
	--address addr_test1vpfwv0ezc5g8a4mkku8hhy3y3vp92t7s3ul8g778g5yegsgalc6gc
	--json
```
Results in an error:
```
Error: The given payment enterprise address 'addr_test1vpfwv0ezc5g8a4mkku8hhy3y3vp92t7s3ul8g778g5yegsgalc6gc' does not belong to the public key in the COSE_Key.
```

<p>&nbsp;<p>&nbsp;

# CIP-36 mode (Catalyst Voting Registration / VotingPower Delegation)

## *Signing - Generate the registration metadata*

![image](https://user-images.githubusercontent.com/47434720/215330136-9d99c86d-9545-4d8f-a79e-5806e98f5974.png)
	      
### Register/Delegate to a single voting-key with minimal parameters (Mainnet example)
``` console
cardano-signer sign --cip36 \
	--payment-address "addr1v9ux8dwy800s5pnq327g9uzh8f2fw98ldytxqaxumh3e8kqumfr6d" \
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
	--payment-address "addr1v9ux8dwy800s5pnq327g9uzh8f2fw98ldytxqaxumh3e8kqumfr6d" \
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
      --payment-address "addr_test1qrlvt2gzuvrhq7m2k00rsyzfrrqwx085cdqgum7w5nc2rxwpxkp2ajdyflxxmxztuqpu2pvvvc8p6tl3xu8a3dym5uls50mr97" \
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
      --payment-address "addr_test1qrlvt2gzuvrhq7m2k00rsyzfrrqwx085cdqgum7w5nc2rxwpxkp2ajdyflxxmxztuqpu2pvvvc8p6tl3xu8a3dym5uls50mr97" \
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
	--payment-address "addr_test1qrlvt2gzuvrhq7m2k00rsyzfrrqwx085cdqgum7w5nc2rxwpxkp2ajdyflxxmxztuqpu2pvvvc8p6tl3xu8a3dym5uls50mr97" \
	--secret-key "f5beaeff7932a4164d270afde7716067582412e8977e67986cd9b456fc082e3a" \
	--vote-public-key ../myvote.voting.pkey --vote-weight 1 \
	--vote-public-key vote-test.vkey --vote-weight 5 \
	--nonce 123456789 \
	--testnet-magic 1 \
	--json-extended
```
The output is a **way more detailed json** format, it contains the raw cbor output in the `.output.cbor` key, and the human-readable format in the `.output.json` key:
``` json
{
  "workMode": "sign-cip36",
  "votePurpose": "Catalyst (0)",
  "totalVoteWeight": 6,
  "paymentAddressHex": "00fec5a902e307707b6ab3de38104918c0e33cf4c3408e6fcea4f0a199c13582aec9a44fcc6d984be003c5058c660e1d2ff1370fd8b49ba73f",
  "paymentAddressType": "payment base",
  "paymentAddressNetwork": "testnet",
  "signDataHex": "1ebe4301d8db0af3c65682e8c9c70c0a22ecc474824d4688b6c24936b9d69fd4",
  "signature": "c5e380e1282b54d6e2f9004e73c533c5e1b135b81076859ff606a16dde410f8375164fc4c4d6c11e43633228687580b5bab02b3181908715f74efdefd2e63902",
  "secretKey": "f5beaeff7932a4164d270afde7716067582412e8977e67986cd9b456fc082e3a",
  "publicKey": "86870efc99c453a873a16492ce87738ec79a0ebd064379a62e2c9cf4e119219e",
  "output": {
    "cbor": "a219ef64a5018282582051f117d26e29aea7db3d1f2f874ab5f585f619a95aed6d71d31a7404cb6557b501825820755b017578b701dc9ddd4eaee67015b4ca8baf66293b7b1d204df426c0ceccb90502582086870efc99c453a873a16492ce87738ec79a0ebd064379a62e2c9cf4e119219e03583900fec5a902e307707b6ab3de38104918c0e33cf4c3408e6fcea4f0a199c13582aec9a44fcc6d984be003c5058c660e1d2ff1370fd8b49ba73f041a075bcd15050019ef65a1015840c5e380e1282b54d6e2f9004e73c533c5e1b135b81076859ff606a16dde410f8375164fc4c4d6c11e43633228687580b5bab02b3181908715f74efdefd2e63902",
    "json": {
      "61284": {
        "1": [
          [
            "0x51f117d26e29aea7db3d1f2f874ab5f585f619a95aed6d71d31a7404cb6557b5",
            1
          ],
          [
            "0x755b017578b701dc9ddd4eaee67015b4ca8baf66293b7b1d204df426c0ceccb9",
            5
          ]
        ],
        "2": "0x86870efc99c453a873a16492ce87738ec79a0ebd064379a62e2c9cf4e119219e",
        "3": "0x00fec5a902e307707b6ab3de38104918c0e33cf4c3408e6fcea4f0a199c13582aec9a44fcc6d984be003c5058c660e1d2ff1370fd8b49ba73f",
        "4": 123456789,
        "5": 0
      },
      "61285": {
        "1": "0xc5e380e1282b54d6e2f9004e73c533c5e1b135b81076859ff606a16dde410f8375164fc4c4d6c11e43633228687580b5bab02b3181908715f74efdefd2e63902"
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


&nbsp;<p>&nbsp;<p>

# KeyGeneration mode

![image](https://github.com/gitmachtl/cardano-signer/assets/47434720/dcc0119f-cab5-4645-a439-35aeedc27e29)

## *Normal ed25519 keypair without derivation-path/mnemonics*

### Generate a keypair in hex-format
``` console
cardano-signer keygen
```
Output - secretKey & publicKey (hex) :
```
1e0e5b1614ad54e170a43ce74fd53e29217ec4ba341d9ad52d97c30ba696bb9c 1d8f971d0b8553981c90e1b5d2884e8190b21f5547c2a784fc65c59cf022d4b2
```
You can generate a nice json output via the `--json` or `--json-extended` flag
``` console
cardano-signer keygen --json-extended
```
``` json
{
  "workMode": "keygen",
  "secretKey": "629ebc4ca6ace67f7b427bf728b39aa5d7bb2f8851f88575d8cee8d112a0956c",
  "publicKey": "f987631d2e136fc9905f8f7f27a8654a5f86834e118c2873d805f2573e41d0c2",
  "output": {
    "skey": {
      "type": "PaymentSigningKeyShelley_ed25519",
      "description": "Payment Signing Key",
      "cborHex": "5820629ebc4ca6ace67f7b427bf728b39aa5d7bb2f8851f88575d8cee8d112a0956c"
    },
    "vkey": {
      "type": "PaymentVerificationKeyShelley_ed25519",
      "description": "Payment Verification Key",
      "cborHex": "5820f987631d2e136fc9905f8f7f27a8654a5f86834e118c2873d805f2573e41d0c2"
    }
  }
}
```
<br>

### Generate .skey/.vkey files

You can also directly generate .skey/.vkey files via the `--out-skey` & `--out-vkey` parameter
``` console
cardano-signer keygen --json-extended \
                    --out-skey test.skey \
		    --out-vkey test.vkey
```
This generates the typical .skey/.vkey files with content like
``` json
{
      "type": "PaymentSigningKeyShelley_ed25519",
      "description": "Payment Signing Key",
      "cborHex": "5820629ebc4ca6ace67f7b427bf728b39aa5d7bb2f8851f88575d8cee8d112a0956c"
}
```
``` json
{
      "type": "PaymentVerificationKeyShelley_ed25519",
      "description": "Payment Verification Key",
      "cborHex": "5820f987631d2e136fc9905f8f7f27a8654a5f86834e118c2873d805f2573e41d0c2"
}
```

<br>

## *ed25519-extended keys with a derivation-path*

### Generate a keypair from the standard payment path
``` console
cardano-signer keygen \
	--path 1852H/1815H/0H/0/0 \
	--json-extended
```
Output - JSON Format:
``` json
{
  "workMode": "keygen",
  "path": "1852H/1815H/0H/0/0",
  "mnemonics": "snap siege fatal leopard label thunder rely trap robot identify someone exclude glance spring right rude tower pluck explain mouse scheme sister onion include",
  "secretKey": "60f0a79e0776b4063d7bff8ada6a37b5fb79168d5e844b51e45fa5088eac6558f858251fdfd2fc55488fceb448c5d8f5d1c93cea5505df05efed86efd90ded6d4db6843876f0154e7d5ab14ddec3dacb353b44d38b9a5a03bde142b5cedf52479eeb435bd154d50e80b2980900ac2d8237408ae373daf68d19b6013f5fcd2ef2",
  "publicKey": "4db6843876f0154e7d5ab14ddec3dacb353b44d38b9a5a03bde142b5cedf5247",
  "XpubKeyHex": "f1d184dc020c90ed0ab318f98b2bbf0b215723d3e68121fba9b12bd5389fa9a3cb01f7d31f63fd73c7406a4381066c747b2cc6eafccbc1f85eb24f664238216a",
  "XpubKeyBech": "xpub178gcfhqzpjgw6z4nrruck2alpvs4wg7nu6qjr7afky4a2wyl4x3ukq0h6v0k8ltncaqx5supqek8g7evcm40ej7plp0tynmxgguzz6sm2mv70",
  "output": {
    "skey": {
      "type": "PaymentExtendedSigningKeyShelley_ed25519_bip32",
      "description": "Payment Signing Key",
      "cborHex": "588060f0a79e0776b4063d7bff8ada6a37b5fb79168d5e844b51e45fa5088eac6558f858251fdfd2fc55488fceb448c5d8f5d1c93cea5505df05efed86efd90ded6d4db6843876f0154e7d5ab14ddec3dacb353b44d38b9a5a03bde142b5cedf52479eeb435bd154d50e80b2980900ac2d8237408ae373daf68d19b6013f5fcd2ef2"
    },
    "vkey": {
      "type": "PaymentVerificationKeyShelley_ed25519",
      "description": "Payment Verification Key",
      "cborHex": "58204db6843876f0154e7d5ab14ddec3dacb353b44d38b9a5a03bde142b5cedf5247"
    }
  }
}
```
As you can see, this generates a new keypair with random mnemonics for the given derivation path `1852H/1815H/0H/0/0`. You can also use the format "1852'/1815'/0'/0/0" for the path, just make sure you put the whole path in doublequotes. 

This generated mnemonics are in the Shelley(Icarus) standard BIP39 format and will work with all major wallets like Eternl, Typhoon, etc.

Also a `Xpub...` key was generated, which can be used to view wallet data in external tracking apps.
<br>

### Generate .skey/.vkey files

Like with the normal ed25519 keys, use the `--out-skey` & `--out-vkey` parameters to directly write out .skey/.vkey files.
``` console
cardano-signer keygen \
	--path 1852H/1815H/0H/2/0 \
	--json-extended \
	--out-skey stake.skey \
	--out-vkey stake.vkey
```
This generates the typical .skey/.vkey files with content like
``` json
{
  "type": "StakeExtendedSigningKeyShelley_ed25519_bip32",
  "description": "Stake Signing Key",
  "cborHex": "5880f0e78e6c657812e10359bce03c14dda79cd27748571e153f477f0eeca741f049022fe2e261bbda8bcedb96b3ec82eb994b80a739ad0e06fe560f59ae8df50bbea74b785851b0d36b8add6dc24d94112fe18e9fa4e60cc0e420002f77b5ce81482632a8abbe24b57b25912eea26ba686786ea45d4c08d67a8c1207ac219467a82"
}
```
``` json
{
  "type": "StakeVerificationKeyShelley_ed25519",
  "description": "Stake Verification Key",
  "cborHex": "5820a74b785851b0d36b8add6dc24d94112fe18e9fa4e60cc0e420002f77b5ce8148"
}
```

<br>

## *CIP36 voting keys without/with mnemonics*

### Generate a keypair from the specific 1694H/1815H/0H/0/0 CIP36 path without mnemonics
``` console
cardano-signer keygen \
	--cip36 \
	--json-extended
```
Output - JSON Format:
``` json
{
  "workMode": "keygen-cip36",
  "path": "1694H/1815H/0H/0/0",
  "votePurpose": "Catalyst (0)",
  "mnemonics": "sudden release husband tone know ladder couple timber another human horn humble exit gift depth green aspect annual crawl final garage innocent cluster aisle",
  "secretKey": "38483eb792e0e4daa12a317ffdeaddd72b3dfde549ee174ecaabf14173bb315dbe3f42605e7400f1616a73a4c08b7f6a89d3e3da87adab9c5e8571bc58bf32d336fdc791592d144da05165c89323c98078d4a888bf4d6e4e146192493d23a065e31ab5741b2180735bd168d2d1a0911e874beb32651f7519733444f3df8bc956",
  "publicKey": "36fdc791592d144da05165c89323c98078d4a888bf4d6e4e146192493d23a065",
  "XpubKeyHex": "792ca6f66a4a37769e24de762b4a79a1b4340c5f5388b9e9fc3ad16f63a1188f766b14cd0d5d5bcd2f8c7bdaef983b7539b24911d92c136ef54d78aa61b564c8",
  "XpubKeyBech": "xpub10yk2dan2fgmhd83ymemzkjne5x6rgrzl2wytn60u8tgk7caprz8hv6c5e5x46k7d97x8hkh0nqah2wdjfygajtqndm656792vx6kfjqr7hegx",
  "secretKeyBech": "cvote_sk18pyradujurjd4gf2x9llm6ka6u4nml09f8hpwnk240c5zuamx9wmu06zvp08gq83v9488fxq3dlk4zwnu0dg0tdtn30g2udutzln95eklhrezkfdz3x6q5t9ezfj8jvq0r223z9lf4hyu9rpjfyn6gaqvh334dt5rvscqu6m695d95dqjy0gwjltxfj37agewv6yfu7l30y4v0wn82x",
  "publicKeyBech": "cvote_vk1xm7u0y2e952ymgz3vhyfxg7fspudf2yghaxkuns5vxfyj0fr5pjss26uda",
  "output": {
    "skey": {
      "type": "CIP36VoteExtendedSigningKey_ed25519",
      "description": "undefined Vote Signing Key",
      "cborHex": "588038483eb792e0e4daa12a317ffdeaddd72b3dfde549ee174ecaabf14173bb315dbe3f42605e7400f1616a73a4c08b7f6a89d3e3da87adab9c5e8571bc58bf32d336fdc791592d144da05165c89323c98078d4a888bf4d6e4e146192493d23a065e31ab5741b2180735bd168d2d1a0911e874beb32651f7519733444f3df8bc956"
    },
    "vkey": {
      "type": "CIP36VoteVerificationKey_ed25519",
      "description": "undefined Vote Verification Key",
      "cborHex": "582036fdc791592d144da05165c89323c98078d4a888bf4d6e4e146192493d23a065"
    }
  }
}
```
Providing the `--cip36` flag sets the parameters to generate CIP36 conform voting key.

You can achieve the same result by setting `--path 1694H/1815H/0H/0/0` or using the shortcut `--path cip36`.

Like with the examples before, you can write out .skey/.vkey files if needed.

Such a generated voting key can be used to be included in the CIP36(Catalyst) registration metadata, which can also be generated & signed by cardano-signer. You can delegate Voting-Power to such a voting key. Later on you can restore a Wallet in a dApp enabled LightWallet like Eternl with the generated mnemonics to do the Voting via the VotingCenter.

<br>

### Generate a keypair with given mnemonics
``` console
cardano-signer keygen \
	--path 1694H/1815H/0H/0/0 \
	--mnemonics "noise dad blood spell fiber valley pact dial nest arrow umbrella addict skill excuse duty hover lyrics enrich now zebra draft sample city hair" \
	--json-extended
```
Output - JSON Format:
``` json
{
  "workMode": "keygen",
  "path": "1694H/1815H/0H/0/0",
  "votePurpose": "Catalyst (0)",
  "mnemonics": "noise dad blood spell fiber valley pact dial nest arrow umbrella addict skill excuse duty hover lyrics enrich now zebra draft sample city hair",
  "secretKey": "106c158474bf7cc634bd4368c69d83a0d9930fbb8036f4905beec7b5f82e6547ad08887117afa7c7fb452e831c1c157d53168b5ccf2a349964485be877d69cf88f1c138a9a1d9c54c38881cdd46aeaf7b409c2dab30d168344934d34299a6dea5744838cd3d3916f0cda808bb91f512162cc58be3ca9b87cb4b69db7e5558861",
  "publicKey": "8f1c138a9a1d9c54c38881cdd46aeaf7b409c2dab30d168344934d34299a6dea",
  "XpubKeyHex": "81d2f04ba976badf5f83711c904898f26f08c64de2185b3fb3c46fdb7f37bae4e093e35996924a30f98a169d862f57b248cb95eb77ba50ce4d24b76c1859e21a",
  "XpubKeyBech": "xpub1s8f0qjafw6ad7hurwywfqjyc7fhs33jdugv9k0anc3haklehhtjwpylrtxtfyj3slx9pd8vx9atmyjxtjh4h0wjseexjfdmvrpv7yxsku9k6z",
  "secretKeyBech": "cvote_sk1zpkptpr5ha7vvd9agd5vd8vr5rvexramsqm0fyzmamrmt7pwv4r66zygwyt6lf78ldzjaqcurs2h65ck3dwv7235n9jysklgwltfe7y0rsfc4xsan32v8zypeh2x46hhksyu9k4np5tgx3ynf56znxndaft5fquv60fezmcvm2qghwgl2ysk9nzchc72nwrukjmfmdl92kyxzczy5xl",
  "publicKeyBech": "cvote_vk13uwp8z56rkw9fsugs8xag6h2776qnsk6kvx3dq6yjdxng2v6dh4qtskqms",
  "output": {
    "skey": {
      "type": "CIP36VoteExtendedSigningKey_ed25519",
      "description": "undefined Vote Signing Key",
      "cborHex": "5880106c158474bf7cc634bd4368c69d83a0d9930fbb8036f4905beec7b5f82e6547ad08887117afa7c7fb452e831c1c157d53168b5ccf2a349964485be877d69cf88f1c138a9a1d9c54c38881cdd46aeaf7b409c2dab30d168344934d34299a6dea5744838cd3d3916f0cda808bb91f512162cc58be3ca9b87cb4b69db7e5558861"
    },
    "vkey": {
      "type": "CIP36VoteVerificationKey_ed25519",
      "description": "undefined Vote Verification Key",
      "cborHex": "58208f1c138a9a1d9c54c38881cdd46aeaf7b409c2dab30d168344934d34299a6dea"
    }
  }
}
```
If you provide mnemonics via the `--mnemonics` parameter, these mnemonics will be used to derive the keys from. So you can also for example convert your Daedalus Wallet into .skey/.vkey files.
<br>

## *dRep keys without/with mnemonics*

### Generate a keypair from the dRep specific path 1852H/1815H/0H/3/0 without mnemonics
``` console
cardano-signer keygen \
	--path drep \
	--json-extended
```
Output - JSON Format:
``` json
{
  "workMode": "keygen",
  "path": "1852H/1815H/0H/3/0",
  "mnemonics": "spirit poverty boring zero banner argue cream bag damage menu purity project scatter harsh moment exit tribe security autumn bar olive defy slight mirror",
  "secretKey": "00ff6013126074c9cfa811c3b7fe02c92d90b7eab4917067043b83f11a9cff4aab46e483282e058b8626a21441c337b26124d2d6cdf9ad8cf90ed179a74c5381395392af20002accd13ca5e4fe1860882ebe2f7f736f7004e39512feb25241af9ee678410593fb9a10d10f21b18457502bfb578d168acfb9bf7418a662bf17bd",
  "publicKey": "395392af20002accd13ca5e4fe1860882ebe2f7f736f7004e39512feb25241af",
  "XpubKeyHex": "a91179e1ab2f8b7866f27a298b8004aab4981739b106fbf96b877bde63a400fe02bb92856c70bffb4389b815e64cafda1a14b447489324153d1075fdd8ea051d",
  "XpubKeyBech": "xpub14yghncdt979hsehj0g5chqqy426fs9eekyr0h7ttsaaaucayqrlq9wujs4k8p0lmgwyms90xfjha5xs5k3r53yeyz573qa0amr4q28g9pgywh",
  "drepIdHex": "f05f78a15b2db995bee537ce2e8220c068c5be44422eed27e129ac71",
  "drepIdBech": "drep17p0h3g2m9kuet0h9xl8zaq3qcp5vt0jygghw6flp9xk8z7cz8zm",
  "secretKeyBech": "drep_sk1qrlkqycjvp6vnnagz8pm0lszeykepdl2kjghqecy8wplzx5ula92k3hysv5zupvtscn2y9zpcvmmycfy6ttvm7dd3nusa5te5ax98qfe2wf27gqq9txdz099unlpscyg96lz7lmndacqfcu4ztlty5jp470wv7zpqkflhxss6y8jrvvy2agzh76h35tg4naeha6p3fnzhutm6jmxnf3",
  "publicKeyBech": "drep_vk189fe9teqqq4ve5fu5hj0uxrq3qhtutmlwdhhqp8rj5f0avjjgxhsu2h6h8",
  "output": {
    "skey": {
      "type": "DRepExtendedSigningKey_ed25519_bip32",
      "description": "Delegate Representative Signing Key",
      "cborHex": "588000ff6013126074c9cfa811c3b7fe02c92d90b7eab4917067043b83f11a9cff4aab46e483282e058b8626a21441c337b26124d2d6cdf9ad8cf90ed179a74c5381395392af20002accd13ca5e4fe1860882ebe2f7f736f7004e39512feb25241af9ee678410593fb9a10d10f21b18457502bfb578d168acfb9bf7418a662bf17bd"
    },
    "vkey": {
      "type": "DRepVerificationKey_ed25519",
      "description": "Delegate Representative Verification Key",
      "cborHex": "5820395392af20002accd13ca5e4fe1860882ebe2f7f736f7004e39512feb25241af"
    }
  }
}
```
As you can see, the path is recognized as a dRep Signing/Verification key path.

You can achieve the same result by setting `--path 1852H/1815H/0H/3/0`.

Like with the examples before, you can write out .skey/.vkey files if needed.

Such a generated key can be used to registere it on chain as your dRep key. You can also use the generated mnemonics to create a new wallet on a LightWallet like Eternl, if you like to have your keys synced.

<br>

### Generate a keypair with given mnemonics and with an extended verification key as an example
``` console
cardano-signer keygen \
	--path 1852H/1815H/0H/3/0 \
	--mnemonics "spirit poverty boring zero banner argue cream bag damage menu purity project scatter harsh moment exit tribe security autumn bar olive defy slight mirror" \
	--vkey-extended
	--json-extended
```
Output - JSON Format:
``` json
{
  "workMode": "keygen",
  "path": "1852H/1815H/0H/3/0",
  "mnemonics": "spirit poverty boring zero banner argue cream bag damage menu purity project scatter harsh moment exit tribe security autumn bar olive defy slight mirror",
  "secretKey": "00ff6013126074c9cfa811c3b7fe02c92d90b7eab4917067043b83f11a9cff4aab46e483282e058b8626a21441c337b26124d2d6cdf9ad8cf90ed179a74c5381395392af20002accd13ca5e4fe1860882ebe2f7f736f7004e39512feb25241af9ee678410593fb9a10d10f21b18457502bfb578d168acfb9bf7418a662bf17bd",
  "publicKey": "395392af20002accd13ca5e4fe1860882ebe2f7f736f7004e39512feb25241af9ee678410593fb9a10d10f21b18457502bfb578d168acfb9bf7418a662bf17bd",
  "XpubKeyHex": "a91179e1ab2f8b7866f27a298b8004aab4981739b106fbf96b877bde63a400fe02bb92856c70bffb4389b815e64cafda1a14b447489324153d1075fdd8ea051d",
  "XpubKeyBech": "xpub14yghncdt979hsehj0g5chqqy426fs9eekyr0h7ttsaaaucayqrlq9wujs4k8p0lmgwyms90xfjha5xs5k3r53yeyz573qa0amr4q28g9pgywh",
  "drepIdHex": "1d40bb22a16442babf911c345736c4d4e07fcc3b3444690785764141",
  "drepIdBech": "drep1r4qtkg4pv3pt40u3rs69wdky6ns8lnpmx3zxjpu9weq5z68dgyg",
  "secretKeyBech": "drep_sk1qrlkqycjvp6vnnagz8pm0lszeykepdl2kjghqecy8wplzx5ula92k3hysv5zupvtscn2y9zpcvmmycfy6ttvm7dd3nusa5te5ax98qfe2wf27gqq9txdz099unlpscyg96lz7lmndacqfcu4ztlty5jp470wv7zpqkflhxss6y8jrvvy2agzh76h35tg4naeha6p3fnzhutm6jmxnf3",
  "publicKeyBech": "drep_vk189fe9teqqq4ve5fu5hj0uxrq3qhtutmlwdhhqp8rj5f0avjjgxheaencgyze87u6zrgs7gd3s3t4q2lm27x3dzk0hxlhgx9xv2l300gge7d87",
  "output": {
    "skey": {
      "type": "DRepExtendedSigningKey_ed25519_bip32",
      "description": "Delegate Representative Signing Key",
      "cborHex": "588000ff6013126074c9cfa811c3b7fe02c92d90b7eab4917067043b83f11a9cff4aab46e483282e058b8626a21441c337b26124d2d6cdf9ad8cf90ed179a74c5381395392af20002accd13ca5e4fe1860882ebe2f7f736f7004e39512feb25241af9ee678410593fb9a10d10f21b18457502bfb578d168acfb9bf7418a662bf17bd"
    },
    "vkey": {
      "type": "DRepExtendedVerificationKey_ed25519_bip32",
      "description": "Delegate Representative Verification Key",
      "cborHex": "5840395392af20002accd13ca5e4fe1860882ebe2f7f736f7004e39512feb25241af9ee678410593fb9a10d10f21b18457502bfb578d168acfb9bf7418a662bf17bd"
    }
  }
}
```
If you provide mnemonics via the `--mnemonics` parameter, these mnemonics will be used to derive the keys from. So you can also for example convert your LightWallet (Eternl, Typhon, ...) into .skey/.vkey files.
<br>

<br>
<br>

## Release Notes / Change-Logs

* **1.14.0**
  #### New dRep-Key generation mode:
	- generate conway dRep keys via the path `--path drep` or
 	- generate conway dRep keys from the derivation path `1852'/1815'/acc'/3/idx'`
  	- generate conway dRep keys from mnemonics or let cardano-signer generate new mnemonics for you

  #### Key generation mode changes:
  	- the flag `with-chain-code` has been replaced by the new flag `vkey-extended`. this makes it easier for the users to understand the meaning
  	- per default the public keys are now always generated as non-extended keys, the secret keys are always extended ones if derived from a path

  #### General
  	- code cleanup

* **1.13.0**
  #### New key generation mode:
  	- generate normal ed25519 keys
	- generate extended ed25519 keys from a derivation path like "1852H/1815H/0H/0/0"
	- generate keys from mnemonics or let cardano-signer generate new mnemonics for you
	- generate CIP36 conform vote keys incl. bech `cvote_vk` data and an optional vote_purpose
	- generate keys with or without chaincode attached
	- directly write out `.skey`/`.vkey` files (like cardano-cli)
	- extended information like an `Xpub...` key is available via the `--json-extended` flag
	- shortcuts for paths can be used like `--path payment`, `--path stake`, `--path cip36`

* **1.12.1**
  #### CIP-36 update:
	- Changed the `--rewards-address` parameter to `--payment-address` parameter. This reflects the latest changes in CIP-36
	- Also the keys for `rewardsAddressHex`,`rewardsAddressType` and `rewardsAddressNetwork` in the `--json-extended` output are not renamed to `paymentAddressHex`, `paymentAddressType`, `paymentAddressNetwork`
	      
* **1.12.0**
  #### General:
  	- The output via `--json-extended` is now showing more details about the address (hex, type, network)
	- The help description can now be displayed for each sub command like: `cardano-signer sign --cip8 --help`
	- Addresses provided via the `--address` parameter can now be a bech-address, hex-string or the path to a file containing the bech-address (typical mywallet.addr) files
  #### CIP-8 / CIP-30 updates:
	- Completely reworked CIP-8/CIP-30 code. Flags `--cip8` & `--cip30` will currently do the same, because CIP-30 uses CIP-8 signing.
	- Signing a payload now generates a full COSE_Sign1 signature together with the COSE_Key publicKey
	- The payload can be set to hashed via the new flag `--hashed`
	- The payload can be excluded from the COSE_Sign1 signature with the new flag `--nopayload`
	- The signing address will be automatically checked against the publicKey (signing and verification)
	- Extended data structure check of the given COSE_Sign1 & COSE_Key
	- Verification can be done against the COSE_Sign1 & COSE_Key, and optionally also against a given payload and address
	- The output via `--json-extended` shows additional information if the payload is hashed, address infos, etc.

* **1.11.0**
  #### General:
  	- Added an optional flag `--bech` (also `--jcli` works), to output the signature and public key in jcli compatible bech format with prefixes `ed25519_sig` and `ed25519_pk`. This is available in the normal signing mode.
	- The verify function now also accepts bech encoded signatures `ed25519_sig` in addition to hex strings.
	- With this update the sign/verify functions in **cardano-signer can substitute jcli** for sign/verify.

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
