## Sign & verify data with a Cardano Secret/Public-Key<br>Sign & verify CIP-8, CIP-30 & CIP-36 data (Catalyst)<br>Generate Cardano-Keys from (Hardware)-Mnemonics and Derivation-Paths<br>Canonize, Hash & Sign Governance Metadata CIP-100/108/119<br>Generate and Verify CIP-88v2 Calidus-Pool-Key data

<img src="https://user-images.githubusercontent.com/47434720/190806957-114b1342-7392-4256-9c5b-c65fc0068659.png" align=right width=40%></img>

&nbsp;<p>

### What can cardano-signer sign/generate?
* **Sign** any hexdata, textdata or binaryfile with a provided normal or extended secret key. The key can be provided in hex, bech or file format. The signing output is a signature in hex- or json-format, also the public key of the provided secret key for verification. With the enabled `--jcli` flag the generated signature and public key will be return in a **jcli** compatible bech format. **Cardano-signer can be used instead of jcli for signing**.
* Sign payloads in **CIP-8 / CIP-30** mode, hashed or not hashed, with or without a payload in the output. The signing output is a COSE_Sign1 signature in hex format and also the public key of the provided secret key for verification. The output can also be set to be in json format which will also show additional data (--json-extended).
* Generate and sign **Catalyst registration/delegation/deregistration** metadata in **CIP-36** mode. This also includes relatively weighted voting power delegation. The output is the registration/delegation or deregistraton data in json or cborHex-format and/or a binary cbor file, which can be transmitted on chain as it is.
* Generate **Cardano Keys** like .skey/.vkey files and hex-keys from **derivation paths**, with or without **mnemonic words**.
* Support for **Hardware-Wallet** derivation types **Ledger & Trezor**.
* Generate conway **dRep Keys, Constitutional Commitee Member Cold/Hot Keys** with or without **mnemonic words**.
* Canonized & Hash CIP-100/108/119 governance metadata jsonld data
* Sign CIP-100/108/119 governacne metadata by adding an authors signature to the document
* Generate CIP-36 voting-keys.
* A given address will automatically be checked against the used publicKey.
* Generate **CIP-88v2 Calidus Pool-Key** registration metadata in CBOR and JSON format

### What can cardano-signer verify?
* **Verify** a signature for any hexdata, textdata or binaryfile together with a provided public key. Also an optional address can be verified against the given public key. The key can be provided in hex, bech or file format. The verification output is true(exitcode=0) or false(exitcode=1) as a console output or in json-format.
* The signature can be provided in hex format or also in bech encoded `ed25519_sig` format. **Cardano-signer can be used instead of jcli for verification**.
* Verify **CIP-8 / CIP-30** COSE_Sign1/COSE_Key data. With hashed or non-hashed payloads. There is also a detailed check on the COSE_Sign1 and COSE_Key data structure included. Verification can be done on the COSE_Sign1 + COSE_Key, or COSE_Sign1 + COSE_Key + payload and/or address.
* Verify **CIP-100/108/119** metadata JSONLD files
* Verify **CIP-88v2 Calidus Pool-Key** registration metadata in CBOR and JSON format

&nbsp;<p>

## Examples
* **[Default mode](#default-mode)**: Sign and verify data with ed25519(cardano) keys
* **[CIP-8 / CIP-30 mode](#cip-8--cip-30-mode)**: COSE_Sign1 signature & COSE_Key publicKey generation/verification
* **[CIP-36 mode](#cip-36-mode-catalyst-voting-registration--votingpower-delegation)**: Generate Catalyst metadata for registration/delegation and also deregistration
* **[KeyGeneration mode](#keygeneration-mode)**: Generate Cardano keys from mnemonics and derivation-paths, also from Ledger/Trezor-HardwareWallets
* **[CIP-100 / CIP-108 / CIP-119 mode](#cip-100--cip-108--cip-119-mode)**: Sign, Verify and Canonize governance metadata
* **[CIP-88v2 Calidus Pool-Key](#cip-88v2-calidus-pool-key-mode)**: Sign & Verify Calidus Key registration metadata
&nbsp;<p>

## Full syntax

``` console

$ cardano-signer help

cardano-signer 1.26.0

Sign a hex/text-string or a binary-file:

   Syntax: cardano-signer sign
   Params: --data-hex "<hex>" | --data "<text>" | --data-file "<path_to_file>"
                                                                data/payload/file to sign in hex-, text- or binary-file-format
           --secret-key "<path_to_file>|<hex>|<bech>"           path to a signing-key-file or a direct signing hex/bech-key string
           [--address "<path_to_file>|<hex>|<bech>"]            optional address check against the signing-key (address-file or a direct bech/hex format)
           [--include-secret]                                   optional flag to include the secret/signing key in the json-extended output
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
           [--nohashcheck]                                      optional flag to not perform a check that the public-key belongs to the address/hash
           [--hashed]                                           optional flag to hash the payload given via the 'data' parameters
           [--nopayload]                                        optional flag to exclude the payload from the COSE_Sign1 signature, default: included
           [--testnet-magic [xxx]]                              optional flag to switch the address check to testnet-addresses, default: mainnet
           [--include-maps]                                     optional flag to include the COSE maps in the json-extended output
           [--include-secret]                                   optional flag to include the secret/signing key in the json-extended output
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
           [--include-secret]                                   optional flag to include the secret/signing key in the json-extended output
           [--json | --json-extended]                           optional flag to generate output in json/json-extended format, default: cborHex(text)
           [--out-file "<path_to_file>"]                        path to an output file, default: standard-output
           [--out-cbor "<path_to_file>"]                        path to write a binary metadata.cbor file to
   Output: Registration-Metadata in JSON-, cborHex-, cborBinary-Format


Sign a Calidus-Pool-PublicKey registration with a Pool-Cold-Key in CIP-88v2 mode:

   Syntax: cardano-signer sign --cip88
   Params: --calidus-public-key "<path_to_file>|<hex>|<bech>"   public-key-file or public hex/bech-key string to use as the new calidus-key
           --secret-key "<path_to_file>|<hex>|<bech>"           signing-key-file or a direct signing hex/bech-key string of the stakepool
           [--nonce <unsigned_int>]                             optional nonce value, if not provided the mainnet-slotHeight calculated from current machine-time will be used
           [--include-secret]                                   optional flag to include the secret/signing key in the json-extended output
           [--json | --json-extended]                           optional flag to generate output in json/json-extended format, default: cborHex(text)
           [--out-file "<path_to_file>"]                        path to an output file, default: standard-output
           [--out-cbor "<path_to_file>"]                        path to write a binary metadata.cbor file to
   Output: Registration-Metadata in JSON-, cborHex-, cborBinary-Format


Sign a governance JSON-LD metadata file with a Secret-Key (add authors, ed25519/CIP-8 algorithm):

   Syntax: cardano-signer sign --cip100
   Params: --data "<jsonld-text>" | --data-file "<path_to_jsonld_file>"
                                                                data or file in jsonld format to sign
           --secret-key "<path_to_file>|<hex>|<bech>"           path to a signing-key-file or a direct signing hex/bech-key string
           --author-name "<name-of-signing-author>"             name of the signing author f.e. "John Doe"
           [--address "<path_to_file>|<hex>|<bech>"]            optional path to an address/id-file or a direct bech/hex format 'stake1..., addr1..., drep1...' to sign with CIP-8 algorithm
           [--replace]                                          optional flag to replace the authors entry with the same public-key
           [--out-file "<path_to_file>"]                        path to an output file, default: standard-output
   Output: "Signed JSON-LD Content" or "JSON-HashInfo if --out-file is used"


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
           [--nohashcheck]                                      optional flag to not perform a check that the public-key belongs to the address/hash
           [--include-maps]                                     optional flag to include the COSE maps in the json-extended output
           [--json | --json-extended]                           optional flag to generate output in json/json-extended format
           [--out-file "<path_to_file>"]                        path to an output file, default: standard-output
   Output: "true/false" (exitcode 0/1) or JSON-Format


Verify CIP-88v2 Calidus-Pool-PublicKey registration-data:

   Syntax: cardano-signer verify --cip88
   Params: --data "<json-metadata>" |                           data to verify as json text
           --data-file "<path_to_file>" |                       data to verify as json file
           --data-hex "<hex>"                                   data to verify as cbor-hex-format
           [--include-maps]                                     optional flag to include the COSE maps in the json-extended output
           [--json | --json-extended]                           optional flag to generate output in json/json-extended format
           [--out-file "<path_to_file>"]                        path to an output file, default: standard-output
   Output: "true/false" or JSON-Format


Verify Signatures in CIP-100/108/119/136 governance JSON-LD metadata:

   Syntax: cardano-signer verify --cip100
   Params: --data "<jsonld-text>" | --data-file "<path_to_jsonld_file>"
                                                                data or file in jsonld format to verify
           [--json | --json-extended]                           optional flag to generate output in json/json-extended format
           [--out-file "<path_to_file>"]                        path to an output file, default: standard-output
   Output: "true/false" or JSON-Format


Generate Cardano ed25519/ed25519-extended keys:

   Syntax: cardano-signer keygen
   Params: [--path "<derivationpath>"]                          optional derivation path in the format like "1852H/1815H/0H/0/0" or "1852'/1815'/0'/0/0"
                                                                or predefined names: --path payment, --path stake, --path cip36, --path drep, --path cc-cold,
                                                                                     --path cc-hot, --path pool, --path calidus
           [--mnemonics "word1 word2 ... word24"]               optional mnemonic words to derive the key from (separate via space)
           [--passphrase "passphrase"]                          optional passphrase for --ledger or --trezor derivation method
           [--ledger | --trezor]                                optional flag to set the derivation type to "Ledger" or "Trezor" hardware wallet
           [--cip36]                                            optional flag to generate CIP36 conform vote keys (also using path 1694H/1815H/0H/0/0)
           [--vote-purpose <unsigned_int>]                      optional vote-purpose (unsigned int) together with --cip36 flag, default: 0 (Catalyst)
           [--vkey-extended]                                    optional flag to generate a 64byte publicKey with chain code
           [--json | --json-extended]                           optional flag to generate output in json/json-extended format
           [--out-file "<path_to_file>"]                        path to an output file, default: standard-output
           [--out-skey "<path_to_skey_file>"]                   path to an output skey-file (writes out a typical *.skey json)
           [--out-vkey "<path_to_vkey_file>"]                   path to an output vkey-file (writes out a typical *.vkey json)
           [--out-id "<path_to_id_file>"]                       path to an output id-file (writes out the bech-id of a pool, drep, calidus,...)
           [--out-mnemonics "<path_to_id_file>"]                path to an output mnemonics-file (writes out the used mnemonics into a file)
   Output: "secretKey + publicKey" or JSON-Format               default: hex-format


Canonize&Hash the governance JSON-LD body metadata for author-signatures: (CIP-100)

   Syntax: cardano-signer canonize --cip100
   Params: --data "<jsonld-text>" | --data-file "<path_to_jsonld_file>"
                                                                data or file in jsonld format to canonize and hash
           [--json | --json-extended]                           optional flag to generate output in json/json-extended format
           [--out-canonized "<path_to_file>"]                   path to an output file for the canonized data
           [--out-file "<path_to_file>"]                        path to an output file, default: standard-output
   Output: "HASH of canonized body" or JSON-Format              NOTE: This is NOT the anchor-url-hash!!!

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

![image](https://github.com/user-attachments/assets/8de00aa9-ce1e-4c68-97ae-3cf51766d1fe)

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

![image](https://github.com/user-attachments/assets/f008bf29-47f9-4144-9bdb-0e981cd0bf91)

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
	--json-extended \
	--include-maps
```
This outputs the detailed json inlusive the used COSE maps:
``` json
  "workMode": "verify-cip8",
  "result": "true",
  "addressHex": "617863b5c43bdf0a06608abc82f0573a549714ff69166074dcdde393d8",
  "addressType": "payment enterprise",
  "addressNetwork": "mainnet",
  "payloadDataHex": "48656c6c6f20776f726c64",
  "isHashed": "false",
  "verifyDataHex": "846a5369676e617475726531582aa201276761646472657373581d617863b5c43bdf0a06608abc82f0573a549714ff69166074dcdde393d8404b48656c6c6f20776f726c64",
  "signature": "fc58155f0cee05bc00e7299af1df1f159ac82a46a055786b259657934eff346eec81349d4678ceabc79f213c66a2bdbfd4ea5d9ebdc630bee5ac9cce75cfc001",
  "publicKey": "755b017578b701dc9ddd4eaee67015b4ca8baf66293b7b1d204df426c0ceccb9",
  "maps": {
    "COSE_Key": {
      "1": 1,
      "3": -8,
      "-1": 6,
      "-2": "0x755b017578b701dc9ddd4eaee67015b4ca8baf66293b7b1d204df426c0ceccb9"
    },
    "COSE_Sign1": [
      "0xa201276761646472657373581d617863b5c43bdf0a06608abc82f0573a549714ff69166074dcdde393d8",
      {
        "hashed": false
      },
      "0x48656c6c6f20776f726c64",
      "0xfc58155f0cee05bc00e7299af1df1f159ac82a46a055786b259657934eff346eec81349d4678ceabc79f213c66a2bdbfd4ea5d9ebdc630bee5ac9cce75cfc001"
    ],
    "verifyData": [
      "Signature1",
      "0xa201276761646472657373581d617863b5c43bdf0a06608abc82f0573a549714ff69166074dcdde393d8",
      "0x",
      "0x48656c6c6f20776f726c64"
    ],
    "protectedHeader": {
      "1": -8,
      "address": "0x617863b5c43bdf0a06608abc82f0573a549714ff69166074dcdde393d8"
    }
  }
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

![image](https://github.com/user-attachments/assets/be93a16e-3e41-4b17-a7e2-8a2428833af8)

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
  "derivationPath": "1852H/1815H/0H/0/0",
  "derivationType": "icarus",
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

### Generate .skey/.vkey/.id/.mnemonics files

Like with the normal ed25519 keys, use the `--out-skey` & `--out-vkey` parameters to directly write out .skey/.vkey files.
But since v1.26 you can also directly write out id-files like Pool-ID, DRep-ID, Calidus-ID and the used mnemonics via the parameters `--out-id` & `--out-mnemonics`.
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

Here is an example of a pool-key generation inclusive id and mnemonics
``` console
cardano-signer keygen \
	--path pool \
	--json-extended \
	--out-skey myPool.skey \
	--out-vkey myPool.vkey \
	--out-id myPool.id \
	--out-mnemonics myPool.mnemonics
```
```json
{
  "workMode": "keygen",
  "derivationPath": "1853H/1815H/0H/0H",
  "derivationType": "icarus",
  "mnemonics": "suit want industry omit this alley april critic pyramid hammer grape tribe kiss thank uncle cry dizzy clip rocket bargain alien alert indoor income",
  "rootKey": "e84c124872e157607670dae9786f04b6861e0b5a0d0591affc1c230a71541f484eee30649b8e8b7861280b950b64ae95bbc8f5bc5ebfe185e77b9a8fe5c255564c5cced60e47308b45e23773b03752965f05af023e0092873d6cbb9bdf7067dd",
  "secretKey": "68de999d1f784849051d91e51c2ca03ee21e4d7ff3435e4e6d0d7e0589541f48d1db9fc8d923bf8e80c48a2bf2154a907bd7cf38bd8bc20b87b7109fceecc9aa8d00b47d79e43ddfea595bfb9afcbc0c501848a1b69f2d1496d25dc1e8f0f8e64145b26208ae4034dcd60be9284b4d720abb3d199552bce8218b674b6aff12f1",
  "publicKey": "8d00b47d79e43ddfea595bfb9afcbc0c501848a1b69f2d1496d25dc1e8f0f8e6",
  "XpubKeyHex": "84f39198db32ccb38c1061ce34cc4b1089e995ad9158b18080a6fdb89ffb3f4666ac859addad20f8c788c063d5b5f029c4b230da928544f2d4ca1a9aa260a9fa",
  "XpubKeyBech": "xpub1sneerxxmxtxt8rqsv88rfnztzzy7n9ddj9vtrqyq5m7m38lm8arxdty9ntw66g8cc7yvqc74khczn39jxrdf9p2y7t2v5x565fs2n7s6gjl50",
  "poolIdHex": "0bd4f1ae2306805d768d371137c8a69e7fa3b5486a3c6013e20f48e0",
  "poolIdBech": "pool1p020rt3rq6q96a5dxugn0j9xnel68d2gdg7xqylzpaywqnwl6fv",
  "secretKeyBech": "pool_xsk1dr0fn8gl0pyyjpgaj8j3ct9q8m3puntl7dp4unndp4lqtz25raydrkulervj80uwsrzg52ljz49fq77heuutmz7zpwrmwyylemkvn25dqz68670y8h075k2mlwd0e0qv2qvy3gdknuk3f9kjthq73u8cueq5tvnzpzhyqdxu6c97j2ztf4eq4wearx24908gyx9kwjm2luf0zfyuckz",
  "publicKeyBech": "pool_vk135qtglteus7al6jet0ae4l9up3gpsj9pk60j69yk6fwur68slrnqn9dlyz",
  "output": {
    "skey": {
      "type": "StakePoolExtendedSigningKey_ed25519_bip32",
      "description": "Stake Pool Operator Signing Key",
      "cborHex": "588068de999d1f784849051d91e51c2ca03ee21e4d7ff3435e4e6d0d7e0589541f48d1db9fc8d923bf8e80c48a2bf2154a907bd7cf38bd8bc20b87b7109fceecc9aa8d00b47d79e43ddfea595bfb9afcbc0c501848a1b69f2d1496d25dc1e8f0f8e64145b26208ae4034dcd60be9284b4d720abb3d199552bce8218b674b6aff12f1"
    },
    "vkey": {
      "type": "StakePoolVerificationKey_ed25519",
      "description": "Stake Pool Operator Verification Key",
      "cborHex": "58208d00b47d79e43ddfea595bfb9afcbc0c501848a1b69f2d1496d25dc1e8f0f8e6"
    }
  }
}
```
The 4 files `myPool.skey, myPool.vkey, myPool.id & myPool.mnemonics` have been created. You can also directly see the poolId and other informations in the output json like above.

<br>

## Generate a keypair from Hardware-Wallet Mnemonics

``` console
cardano-signer keygen \
	--path payment \
	--mnemonics "snap siege fatal leopard label thunder rely trap robot identify someone exclude glance spring right rude tower pluck explain mouse scheme sister onion include" \
	--ledger \
	--json-extended
```
Output - JSON Format:
``` json
{
  "workMode": "keygen-ledger",
  "derivationPath": "1852H/1815H/0H/0/0",
  "derivationType": "ledger",
  "mnemonics": "snap siege fatal leopard label thunder rely trap robot identify someone exclude glance spring right rude tower pluck explain mouse scheme sister onion include",
  "secretKey": "f80ad0a24e08aaa39136ae52ab007b0e3b9d1d593b3d170fcaa61a322fcdb95d5e3a846ea94ebbf22ac5ab64abd7583404762bb3850f4c3362a46226ee92eec94c0ffded554c9a6eda379450af9f38640f87aff455129f679996e056697d4190a00c5bcb331ad60daf8b5b0a3fe6dfa2ec48c546f6290a9787cadd566807eb91",
  "publicKey": "4c0ffded554c9a6eda379450af9f38640f87aff455129f679996e056697d4190",
  "XpubKeyHex": "58c80020cc2e6c99e801f6caaa296381673c7ea8aed92cb14b5229dc7434acc97c04b33d3aa811847957f4f82965e7d4e2a7273b67f251c22bfca5dcdfd44c03",
  "XpubKeyBech": "xpub1tryqqgxv9ekfn6qp7m9252trs9nncl4g4mvjev2t2g5acap54nyhcp9n85a2syvy09tlf7pfvhnafc48yuak0uj3cg4lefwuml2ycqc3457ta",
  "output": {
    "skey": {
      "type": "PaymentExtendedSigningKeyShelley_ed25519_bip32",
      "description": "Payment Signing Key",
      "cborHex": "5880f80ad0a24e08aaa39136ae52ab007b0e3b9d1d593b3d170fcaa61a322fcdb95d5e3a846ea94ebbf22ac5ab64abd7583404762bb3850f4c3362a46226ee92eec94c0ffded554c9a6eda379450af9f38640f87aff455129f679996e056697d4190a00c5bcb331ad60daf8b5b0a3fe6dfa2ec48c546f6290a9787cadd566807eb91"
    },
    "vkey": {
      "type": "PaymentVerificationKeyShelley_ed25519",
      "description": "Payment Verification Key",
      "cborHex": "58204c0ffded554c9a6eda379450af9f38640f87aff455129f679996e056697d4190"
    }
  }
}
```
As you can see, this generates a new keypair from the given mnemonics. In this example just a standard payment keypair. The used derivation type was set to `Ledger` hardware wallet. 

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
  "derivationPath": "1694H/1815H/0H/0/0",
  "derivationType": "icarus",
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
  "derivationPath": "1694H/1815H/0H/0/0",
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
  "derivationPath": "1852H/1815H/0H/3/0",
  "derivationType": "icarus",
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

Such a generated key can be used to register it on chain as your dRep key. You can also use the generated mnemonics to create a new wallet on a LightWallet like Eternl, if you like to have your keys synced.

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
  "derivationPath": "1852H/1815H/0H/3/0",
  "derivationType": "icarus",
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

## *Constitutional Commitee Member Cold/Hot keys*

### Generate a CC-Cold keypair from the specific path 1852H/1815H/0H/4/0
``` console
cardano-signer keygen \
	--path cc-cold \
	--json-extended
```
Output - JSON Format:
``` json
{
  "workMode": "keygen",
  "derivationPath": "1852H/1815H/0H/4/0",
  "derivationType": "icarus",
  "mnemonics": "cotton thunder useful social state soft engage member rent subject kite earn forget robot coral depart future betray seed bag acquire enlist time primary",
  "secretKey": "f07d70ee6fe6319bc265256077570a59b715312cf3c268547b7c4da966bc9e5568a67ca09e0f2ccbbbdd4b7c8563bb2e51529da43f2b77fe6db02371aa6dfba168c0ddf7e28f4a1060db367e1b3ec8dc1fa2c6eee2c9e92a7a45f0f4d026b093addcc291d29055a5407e99dcfce83436cf9369a09919bf5e653c680b6b418159",
  "publicKey": "68c0ddf7e28f4a1060db367e1b3ec8dc1fa2c6eee2c9e92a7a45f0f4d026b093",
  "XpubKeyHex": "6a86bb2d7eed40af0fc6bc96bb22cfdfac484570fbf20720e9af467418c12e13abe8b00e84b388298548608477c6ab410ab98582e2457faaf9642e7edcb191fc",
  "XpubKeyBech": "xpub1d2rtktt7a4q27r7xhjttkgk0m7kys3tsl0eqwg8f4ar8gxxp9cf6h69sp6zt8zpfs4yxpprhc645zz4eskpwy3tl4tukgtn7mjcerlq6h05gk",
  "ccColdIdHex": "12de8a19ab0a95aafdb881bf4bdfb092207e89ec2fa0c43be73dbcf1",
  "ccColdIdBech": "cc_cold1zt0g5xdtp2264ldcsxl5hhasjgs8az0v97svgwl88k70zezc2s3",
  "secretKeyBech": "cc_cold_xsk17p7hpmn0uccehsn9y4s8w4c2txm32vfv70pxs4rm03x6je4une2k3fnu5z0q7txth0w5kly9vwaju52jnkjr72mhlekmqgm34fklhgtgcrwl0c50fggxpkek0cdnajxur73vdmhze85j57j97r6dqf4sjwkaes5362g9tf2q06vael8gxsmvlymf5zv3n067v57xszmtgxq4j9q305j",
  "publicKeyBech": "cc_cold_vk1drqdmalz3a9pqcxmxelpk0kgms0693hwuty7j2n6ghc0f5pxkzfsul89qx",
  "output": {
    "skey": {
      "type": "ConstitutionalCommitteeColdExtendedSigningKey_ed25519_bip32",
      "description": "Constitutional Committee Cold Extended Signing Key",
      "cborHex": "5880f07d70ee6fe6319bc265256077570a59b715312cf3c268547b7c4da966bc9e5568a67ca09e0f2ccbbbdd4b7c8563bb2e51529da43f2b77fe6db02371aa6dfba168c0ddf7e28f4a1060db367e1b3ec8dc1fa2c6eee2c9e92a7a45f0f4d026b093addcc291d29055a5407e99dcfce83436cf9369a09919bf5e653c680b6b418159"
    },
    "vkey": {
      "type": "ConstitutionalCommitteeColdVerificationKey_ed25519",
      "description": "Constitutional Committee Cold Verification Key",
      "cborHex": "582068c0ddf7e28f4a1060db367e1b3ec8dc1fa2c6eee2c9e92a7a45f0f4d026b093"
    }
  }
}
```
As you can see, the path is recognized as a CC-Cold Signing/Verification key path.

You can achieve the same result by setting `--path 1852H/1815H/0H/4/0`.

Like with the examples before, you can directly also write out .skey/.vkey files if needed.

**If you wanna use your own mnemonics, just provide them via the `--mnemonics` parameter!**

<br>

### Generate a CC-Hot keypair from the specific path 1852H/1815H/0H/5/0
``` console
cardano-signer keygen \
	--path cc-hot \
	--json-extended
```
Output - JSON Format:
``` json
{
  "workMode": "keygen",
  "derivationPath": "1852H/1815H/0H/5/0",
  "derivationType": "icarus",
  "mnemonics": "knock advance olympic table pride melody cause kick govern pass manual liberty warfare zero now meat confirm chronic amount powder three limb patient ball",
  "secretKey": "401299d0380dec82d938092673de937c634338976bd246b86b9ddcd69838b654b87c0afa9d08df7bbfec137e8b2f98e48de0c01225f7b278b37efad1dfbbaefc344ece677d4931d596210917c7ba6125b6253dd4431a0c886369555235f385a093bca3010d9dadba7489f0f5ec9a7a43239b06326e9fbb3d7685ecf719b90738",
  "publicKey": "344ece677d4931d596210917c7ba6125b6253dd4431a0c886369555235f385a0",
  "XpubKeyHex": "7da8b212c1a0364f2fd08707f8e132a07d67c3e86e50e8f243ba8688403011bd3adfe9de3beed77354ca01887337a3779783250e20d2705a40d930d45220f6cb",
  "XpubKeyBech": "xpub10k5tyykp5qmy7t7ssurl3cfj5p7k0slgdegw3ujrh2rgsspszx7n4hlfmca7a4mn2n9qrzrnx73h09ury58zp5nstfqdjvx52gs0djcpqjpv0",
  "ccHotIdHex": "644d25e82ba444e6bc4f6141968f5f626ac26669d9952f682cdbc90f",
  "ccHotIdBech": "cc_hot1v3xjt6pt53zwd0z0v9qedr6lvf4vyenfmx2j76pvm0ys7qcljwa",
  "secretKeyBech": "cc_hot_xsk1gqffn5pcphkg9kfcpyn88h5n0335xwyhd0fydwrtnhwddxpcke2tslq2l2ws3hmmhlkpxl5t97vwfr0qcqfztaaj0zeha7k3m7a6alp5fm8xwl2fx82evggfzlrm5cf9kcjnm4zrrgxgscmf24frtuu95zfmegcppkw6mwn538c0tmy60fpj8xcxxfhflweaw6z7eacehyrnsf69qu2",
  "publicKeyBech": "cc_hot_vk1x38vuemafycat93ppytu0wnpykmz20w5gvdqezrrd924yd0nsksqah2clh",
  "output": {
    "skey": {
      "type": "ConstitutionalCommitteeHotExtendedSigningKey_ed25519_bip32",
      "description": "Constitutional Committee Hot Extended Signing Key",
      "cborHex": "5880401299d0380dec82d938092673de937c634338976bd246b86b9ddcd69838b654b87c0afa9d08df7bbfec137e8b2f98e48de0c01225f7b278b37efad1dfbbaefc344ece677d4931d596210917c7ba6125b6253dd4431a0c886369555235f385a093bca3010d9dadba7489f0f5ec9a7a43239b06326e9fbb3d7685ecf719b90738"
    },
    "vkey": {
      "type": "ConstitutionalCommitteeHotVerificationKey_ed25519",
      "description": "Constitutional Committee Hot Verification Key",
      "cborHex": "5820344ece677d4931d596210917c7ba6125b6253dd4431a0c886369555235f385a0"
    }
  }
}
```
As you can see, the path is recognized as a CC-Hot Signing/Verification key path.

You can achieve the same result by setting `--path 1852H/1815H/0H/5/0`.

Like with the examples before, you can directly also write out .skey/.vkey files if needed.

**If you wanna use your own mnemonics, just provide them via the `--mnemonics` parameter!**

&nbsp;<p>&nbsp;<p>

# CIP-100 / CIP-108 / CIP-119 mode

## Sign governance metadata and add author(s) field

![image](https://github.com/user-attachments/assets/e6a680c2-8da6-47d8-91cd-5af84ba73d0a)

If you input a JSONLD governance file (context part not shown) like
```json
{
...
  "hashAlgorithm": "blake2b-256",
  "body": {
    "title": "Example CIP108(+CIP100) metadata",
    "abstract": "This metadata was generated to test out db-sync, SPO-Scripts, Koios and other tools...",
    "motivation": "This must work, should be motivation enough.",
    "rationale": "Let's keep testing stuff",
    "references": [
      {
        "@type": "Other",
        "label": "SanchoNet",
        "uri": "https://sancho.network"
      }
    ],
    "comment": "This is an example CIP-108 metadata-file... testing SPO-Scripts, Koios and Co.",
    "externalUpdates": [
      {
        "title": "SPO Scripts",
        "uri": "https://github.com/gitmachtl/scripts"
      },
      {
        "title": "Koios",
        "uri": "https://koios.rest"
      }
    ]
  }
}
```
and running
``` console
cardano-signer.js sign --cip100 \
                       --data-file CIP108-example.json \
                       --secret-key dummy.skey \
                       --author-name "The great Name" \
                       --out-file CIP108-example-signed.json
```

generates you the governance metadata file with the added signature:
```json
{
...
  "hashAlgorithm": "blake2b-256",
  "body": {
    "title": "Example CIP108(+CIP100) metadata",
    "abstract": "This metadata was generated to test out db-sync, SPO-Scripts, Koios and other tools...",
    "motivation": "This must work, should be motivation enough.",
    "rationale": "Let's keep testing stuff",
    "references": [
      {
        "@type": "Other",
        "label": "SanchoNet",
        "uri": "https://sancho.network"
      }
    ],
    "comment": "This is an example CIP-108 metadata-file... testing SPO-Scripts, Koios and Co.",
    "externalUpdates": [
      {
        "title": "SPO Scripts",
        "uri": "https://github.com/gitmachtl/scripts"
      },
      {
        "title": "Koios",
        "uri": "https://koios.rest"
      }
    ]
  },
  "authors": [
    {
      "name": "The great Name",
      "witness": {
        "witnessAlgorithm": "ed25519",
        "publicKey": "755b017578b701dc9ddd4eaee67015b4ca8baf66293b7b1d204df426c0ceccb9",
        "signature": "8b579ba2cb9bcb2355e550a67865d56017d4696a4a48f8db5218a92a7f85bb3ddcde13500b89531c68a3f52deb83ca45f1987ea048500e11feee26847cb6b900"
      }
    }
  ]
}
```

Please notice, if you want to author-sign in `CIP-0008` mode, you must provide an additional address via the `--address` parameter. This can be a filename, bech-address/id or a hex-hash.
``` console
cardano-signer.js sign --cip100 \
                       --data-file CIP108-example.json \
                       --secret-key dummy.skey \
                       --address dummmy.addr \
                       --author-name "The great Name" \
                       --out-file CIP108-example-signed.json
```

Cardano-Signer is doing the following steps to sign the document:
* check that the provided input data is a valid JSON file
* canonize the `@context` and `body` part via URDNA2015 method and hash it via black2b-256 method
* check that the `hashAlgorithm` is `black2b-256`
* check any preexisting `authors` array entry to be valid
* check that there is no duplicated public-key entry
* sign the canonized hash with the provided secret-key and author-name

Additional authors can be added by simply running the same command multiple times! 

Also, if you write out the new file directly via the `--out-file` parameter, the output of cardano-signer becomes a json with the basic infos of the new file, including the `anchorHash`. Ready do be used with governance on Cardano.
```json
{
  "workMode": "sign-cip100",
  "witnessAlgorithm": "CIP-0008",
  "outFile": "CIP108-example-signed.json",
  "anchorHash": "80947b18ad1e75919b103c5613ea69f96e9f27b930a3f17343e22223c5fa3d0f"
}
```

<br>

## Verify governance metadata and the author(s) signatures

![image](https://github.com/user-attachments/assets/97598a29-70f1-4e95-8f3f-deae8f832fb6)

As we already learned, you can use cardano-signer to sign a governance metadata file with author signatures. This function is doing the verification of such documents.

Lets use the same document that we generated above:

``` console
cardano-signer verify --cip100 \
                      --data-file CIP108-example-signed.json \
                      --json-extended
``` 

This gives us the following result:
```json
{
  "workMode": "verify-cip100",
  "result": true,
  "errorMsg": "",
  "authors": [
    {
      "name": "The great Name",
      "publicKey": "755b017578b701dc9ddd4eaee67015b4ca8baf66293b7b1d204df426c0ceccb9",
      "signature": "8b579ba2cb9bcb2355e550a67865d56017d4696a4a48f8db5218a92a7f85bb3ddcde13500b89531c68a3f52deb83ca45f1987ea048500e11feee26847cb6b900",
      "valid": true
    }
  ],
  "canonizedHash": "8b5db60af5d673fcff7c352db569bff595c3279d3db23f2b607607bd694496d1",
  "body": {
    "title": "Example CIP108(+CIP100) metadata",
    "abstract": "This metadata was generated to test out db-sync, SPO-Scripts, Koios and other tools...",
    "motivation": "This must work, should be motivation enough.",
    "rationale": "Let's keep testing stuff",
    "references": [
      {
        "@type": "Other",
        "label": "SanchoNet",
        "uri": "https://sancho.network"
      }
    ],
    "comment": "This is an example CIP-108 metadata-file... testing SPO-Scripts, Koios and Co.",
    "externalUpdates": [
      {
        "title": "SPO Scripts",
        "uri": "https://github.com/gitmachtl/scripts"
      },
      {
        "title": "Koios",
        "uri": "https://koios.rest"
      }
    ]
  },
  "canonizedBody": [
    "_:c14n0 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0100/README.md#comment> \"This is an example CIP-108 metadata-file... testing SPO-Scripts, Koios and Co.\"@en-us .",
    "_:c14n0 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0100/README.md#externalUpdates> _:c14n1 .",
    "_:c14n0 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0100/README.md#externalUpdates> _:c14n3 .",
    "_:c14n0 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0108/README.md#abstract> \"This metadata was generated to test out db-sync, SPO-Scripts, Koios and other tools...\"@en-us .",
    "_:c14n0 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0108/README.md#motivation> \"This must work, should be motivation enough.\"@en-us .",
    "_:c14n0 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0108/README.md#rationale> \"Let's keep testing stuff\"@en-us .",
    "_:c14n0 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0108/README.md#references> _:c14n2 .",
    "_:c14n0 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0108/README.md#title> \"Example CIP108(+CIP100) metadata\"@en-us .",
    "_:c14n1 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0100/README.md#update-title> \"SPO Scripts\"@en-us .",
    "_:c14n1 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0100/README.md#update-uri> \"https://github.com/gitmachtl/scripts\"@en-us .",
    "_:c14n2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0100/README.md#OtherReference> .",
    "_:c14n2 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0100/README.md#reference-label> \"SanchoNet\"@en-us .",
    "_:c14n2 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0100/README.md#reference-uri> \"https://sancho.network\"@en-us .",
    "_:c14n3 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0100/README.md#update-title> \"Koios\"@en-us .",
    "_:c14n3 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0100/README.md#update-uri> \"https://koios.rest\"@en-us .",
    "_:c14n4 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0108/README.md#body> _:c14n0 ."
  ]
}
```

There are some interesting fields to notice:
* `result` : will be `true` or `false` -> this is an overall check result
* `errorMsg` : this is a freeform text, describing any found issues in the document
* `authors` : this is an array of all authors in the document and the signature verification result in the `valid` field
* `canonizedHash` : this holds the hash of the canonized body
* `canonizedBody` : this outputs the canonized body in case you wanna use it for debugging. the next function `canonize` below can also directly write out that canonized body for further usage.

<br>

## Canonize & Hash the body of governance metadata

![image](https://github.com/user-attachments/assets/9fe8403d-e43d-4469-9466-5ee7c07cacb0)

In this mode you can provide a governance metadata json/jsonld file to cardano-signer to canonize
and hash the @context+body content. The hash is needed for verification and signing of the document authors.

``` console
cardano-signer canonize --cip100 --data-file CIP108-example.json
```
Output - Hash of the canonized body content(hex) :
```
8b5db60af5d673fcff7c352db569bff595c3279d3db23f2b607607bd694496d1
```

You can also generate a nice json output via the `--json` or `--json-extended` flag
``` console
cardano-signer canonize --cip100 \
                        --data-file CIP108-example.json \
                        --json-extended
```
``` json
{
  "workMode": "hash-cip100",
  "canonizedHash": "8b5db60af5d673fcff7c352db569bff595c3279d3db23f2b607607bd694496d1",
  "body": {
    "title": "Example CIP108(+CIP100) metadata",
    "abstract": "This metadata was generated to test out db-sync, SPO-Scripts, Koios and other tools...",
    "motivation": "This must work, should be motivation enough.",
    "rationale": "Let's keep testing stuff",
    "references": [
      {
        "@type": "Other",
        "label": "SanchoNet",
        "uri": "https://sancho.network"
      }
    ],
    "comment": "This is an example CIP-108 metadata-file... testing SPO-Scripts, Koios and Co.",
    "externalUpdates": [
      {
        "title": "SPO Scripts",
        "uri": "https://github.com/gitmachtl/scripts"
      },
      {
        "title": "Koios",
        "uri": "https://koios.rest"
      }
    ]
  },
  "canonizedBody": [
    "_:c14n0 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0100/README.md#comment> \"This is an example CIP-108 metadata-file... testing SPO-Scripts, Koios and Co.\"@en-us .",
    "_:c14n0 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0100/README.md#externalUpdates> _:c14n1 .",
    "_:c14n0 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0100/README.md#externalUpdates> _:c14n3 .",
    "_:c14n0 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0108/README.md#abstract> \"This metadata was generated to test out db-sync, SPO-Scripts, Koios and other tools...\"@en-us .",
    "_:c14n0 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0108/README.md#motivation> \"This must work, should be motivation enough.\"@en-us .",
    "_:c14n0 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0108/README.md#rationale> \"Let's keep testing stuff\"@en-us .",
    "_:c14n0 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0108/README.md#references> _:c14n2 .",
    "_:c14n0 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0108/README.md#title> \"Example CIP108(+CIP100) metadata\"@en-us .",
    "_:c14n1 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0100/README.md#update-title> \"SPO Scripts\"@en-us .",
    "_:c14n1 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0100/README.md#update-uri> \"https://github.com/gitmachtl/scripts\"@en-us .",
    "_:c14n2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0100/README.md#OtherReference> .",
    "_:c14n2 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0100/README.md#reference-label> \"SanchoNet\"@en-us .",
    "_:c14n2 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0100/README.md#reference-uri> \"https://sancho.network\"@en-us .",
    "_:c14n3 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0100/README.md#update-title> \"Koios\"@en-us .",
    "_:c14n3 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0100/README.md#update-uri> \"https://koios.rest\"@en-us .",
    "_:c14n4 <https://github.com/cardano-foundation/CIPs/blob/master/CIP-0108/README.md#body> _:c14n0 ."
  ]
}
```

If you're interested in the **raw canonized data**, that can be written out to an extra file using the `--out-canonized` parameter like:
``` console
cardano-signer canonize --cip100 \
                         --data-file CIP108-example.json \
                         --out-canonized CIP108-example.canonized \
                         --json-extended
```
And of course you can write out the plaintext or json output also directly to a file like with the other functions. This is simply done by using the `--out-file` parameter.

<p>&nbsp;<p>&nbsp;

# CIP-88v2 Calidus Pool-Key mode

Cardano-Signer can Sign and Verify the so called Calidus Pool-Key registration metadata. The Calidus Pool-Key is used to identify/authorize pool ownership for public/private services without the need to go thru a VRF-Secret-Key signing process.
The Calidus Pool-Key can be used on the CLI and with LightWallets directly in the Browser for Identification/Login/Authorization/etc. If you wanna update to a new Calidus Key, just generate a new one and register it for the pool.
You only need to sign the registration metadata once with your Stakepool Cold-Key, after that you can use the Calidus Key for various services on a daily base. No need to use the Stakepool Cold-Key or the VRF Secret-Key anymore.
Its a standard ed25519 signing/verification in the end, so there are plenty of libs available for the integration in own services/dApps.

## *Signing - Generate the registration metadata*

![image](https://github.com/user-attachments/assets/cefa22f3-3596-440e-8a17-4db09f164a3b)

Generating the registration metadata with Cardano-Signer is easy. All you need is the Calidus Public-Key as a `*.vkey` file, hex or bech format. You also need the Stakepool Cold-Key for the signing.

### 1. Generate a new Calidus Key with Mnemonics

If there is not already a Calidus Key, than we have to generate a new one first. Its a good idea to directly do this with mnemonics generation, so you can import those mnemonics later on in a LightWallet.
We can use the standard `--path calidus` for this. Lets generate ourself a new Calidus key with the name `myCalidusKey`:

``` console
cardano-signer keygen --path calidus \
	--out-skey myCalidusKey.skey \
	--out-vkey myCalidusKey.vkey \
	--out-id myCalidusKey.id \
	--out-mnemonics myCalidusKey.mnemonics \
	--json-extended
```
The output in json format:
``` json
{
  "workMode": "keygen",
  "derivationPath": "1852H/1815H/0H/0/0",
  "derivationType": "icarus",
  "mnemonics": "clap eye hazard exit blossom help lamp fatigue neck month rely include build link all impose asset correct blood olive cushion garage hundred open",
  "rootKey": "e84ee3b01ecb6516f1f232947a0cfa146ae5deee79083b51da3ecad0c111f75f9aae9463181aef81785a9833199c719fec8a3e5b2bffeddb3bb56ea9f920fed2120339808f21ad5b2c7a1e40706e3ba4e5edc4cd7ea772f5ee3669114528c938",
  "secretKey": "1080c35aa98d7c7e60d585a9c011708874cfe94f96327afdcb871459d211f75ff8b52c7ed88756c448a0023a9375c17db9307030347410e74bf576b311a2a605369b9aa06aa9389d6ba87b524846056c69b8b0221bdeb91bef814f1883cc86c31a16ab2f516a27198c62d78dd64f0d2b94e7d22de03304d4882f6301f443f255",
  "publicKey": "369b9aa06aa9389d6ba87b524846056c69b8b0221bdeb91bef814f1883cc86c3",
  "XpubKeyHex": "23d9cd311ada7e0d93ceb1706b0366049e523e5c1124d001619516ab0bfa9a638f16ed0adef34334b59434b1242dedfbe860a35d517f5dd9dd2b0f8ec1dd8bfc",
  "XpubKeyBech": "xpub1y0vu6vg6mflqmy7wk9cxkqmxqj09y0juzyjdqqtpj5t2kzl6nf3c79hdpt00xse5kk2rfvfy9hklh6rq5dw4zl6am8wjkruwc8wchlq0r67ry",
  "calidusIdHex": "a15f3053586a2d8ec767523b1d8482d97933bc0bcab57f619691903c47",
  "calidusIdBech": "calidus1590nq56cdgkca3m82ga3mpyzm9un80qte26h7cvkjxgrc3chqexdf",
  "output": {
    "skey": {
      "type": "PaymentExtendedSigningKeyShelley_ed25519_bip32",
      "description": "Calidus Pool Signing Key",
      "cborHex": "58801080c35aa98d7c7e60d585a9c011708874cfe94f96327afdcb871459d211f75ff8b52c7ed88756c448a0023a9375c17db9307030347410e74bf576b311a2a605369b9aa06aa9389d6ba87b524846056c69b8b0221bdeb91bef814f1883cc86c31a16ab2f516a27198c62d78dd64f0d2b94e7d22de03304d4882f6301f443f255"
    },
    "vkey": {
      "type": "PaymentVerificationKeyShelley_ed25519",
      "description": "Calidus Pool Verification Key",
      "cborHex": "5820369b9aa06aa9389d6ba87b524846056c69b8b0221bdeb91bef814f1883cc86c3"
    }
  }
}
```

Cardano-Signer generated a new key-pair for you `myCalidusKey.skey & myCalidusKey.vkey`, and also the `myCalidusKey.id` file which holds your calidus-bech-id. In addition you also got a file `myCalidusKey.mnemonics`, which holds the used mnemonic words. You can restore your calidus key in the light wallet of your choice with those mnemonics. In the output JSON, you can also see all those informations.

### 2. Generate the registration metadata

Now that we have a Calidus Key ready, we can generate the registration metadata in JSON or CBOR format. If you wanna take a look at it, just use the JSON format.

As stated above, we need the Calidus Public-Key and the Stakepool Cold-Key for this. In addition you can provide a unique `nonce` to the signer, this `nonce` must be a number higher than your old registration.
In case there is no nonce parameter provided, Cardano-Signer will automatically use the Cardano MainNet slotheight for this. The signature is generated via the CIP8/30 messageSign method, so this can also be used for Stakepool Keys on a Hardware-Wallet.
A special mode for this will follow in an upcoming release.

``` console
cardano-signer sign --cip88 \
	--calidus-public-key myCalidusKey.vkey \
	--secret-key myPoolCold.skey \
        --json \
	--out-file myCalidusRegistrationMetadata.json
```
The output file `myCalidusRegistrationMetadata.json`:
``` json
{
  "867": {
    "0": 2,
    "1": {
      "1": [
        1,
        "0x172641c2c66128b5324be1cb663b8acb3cd66bc808276fd2813ba227"
      ],
      "2": [],
      "3": [
        2
      ],
      "4": 149261016,
      "7": "0x699e69a1f6142252fcc44ca2832ef7f90c94c5860a24fba3efbbd8f5e319b1fa"
    },
    "2": [
      {
        "1": {
          "1": 1,
          "3": -8,
          "-1": 6,
          "-2": "0xce43a34542403e9f61f6384dbe1f3e21c047e050f56aa2c04daaecb4e5340a09"
        },
        "2": [
          "0xa201276761646472657373581c172641c2c66128b5324be1cb663b8acb3cd66bc808276fd2813ba227",
          0,
          "0xaff90146c0b74f1288437fa5a8c2915ea0a24d6e8d0f83a05fbbb46fecf0a7f6",
          "0x5e748ae8602721ad179865b8e678918689d236da7a0d45b4f445c93ca287751bc9091ace25fcb6ef4feb61052809b9a0265c0dd7cdec5e2dc938ba15e78bce0b"
        ]
      }
    ]
  }
}
```

This is the signed registration metadata. All that is left is to use it in a transaction on the Cardano Blockchain.

In case you wanna link more than one pool to the same Calidus Key, just generate another registration metadata signed with the 2nd Pool Cold-Key but using the same Calidus Key.

<br>

## *Verify - Calidus Key registration metadata*

![image](https://github.com/user-attachments/assets/b4387810-bbf5-472a-b0af-4494afaa72f6)

It is of course also possible to verify registration metadata. This metadata can be provided in form of a JSON-File, JSON-Plaintext or as a CBOR-HexString.

### Verify registration metadata provided as a JSON-File

We can show the usecase with the registration file we used in the above signing example:

``` console
cardano-signer verify --cip88 \
	--data-file myCalidusRegistrationMetadata.json \
	--json-extended
```
The output in json format:
``` json
{
  "workMode": "verify-cip88",
  "result": "true",
  "poolIdHex": "172641c2c66128b5324be1cb663b8acb3cd66bc808276fd2813ba227",
  "calidusPublicKey": "699e69a1f6142252fcc44ca2832ef7f90c94c5860a24fba3efbbd8f5e319b1fa",
  "publicKey": "ce43a34542403e9f61f6384dbe1f3e21c047e050f56aa2c04daaecb4e5340a09",
  "nonce": 149261016,
  "payloadCbor": "a5018201581c172641c2c66128b5324be1cb663b8acb3cd66bc808276fd2813ba2270280038102041a08e58ad8075820699e69a1f6142252fcc44ca2832ef7f90c94c5860a24fba3efbbd8f5e319b1fa",
  "payloadHash": "aff90146c0b74f1288437fa5a8c2915ea0a24d6e8d0f83a05fbbb46fecf0a7f6",
  "isHashed": "false",
  "verifyDataHex": "aff90146c0b74f1288437fa5a8c2915ea0a24d6e8d0f83a05fbbb46fecf0a7f6",
  "coseSign1Hex": "845829a201276761646472657373581c172641c2c66128b5324be1cb663b8acb3cd66bc808276fd2813ba227a166686173686564f45820aff90146c0b74f1288437fa5a8c2915ea0a24d6e8d0f83a05fbbb46fecf0a7f658405e748ae8602721ad179865b8e678918689d236da7a0d45b4f445c93ca287751bc9091ace25fcb6ef4feb61052809b9a0265c0dd7cdec5e2dc938ba15e78bce0b",
  "coseKeyHex": "a4010103272006215820ce43a34542403e9f61f6384dbe1f3e21c047e050f56aa2c04daaecb4e5340a09",
  "coseSignature": "5e748ae8602721ad179865b8e678918689d236da7a0d45b4f445c93ca287751bc9091ace25fcb6ef4feb61052809b9a0265c0dd7cdec5e2dc938ba15e78bce0b"
}
```

This is the extended json output with a lot of data in case you wanna use it in your own application. If you wanna check the registration metadata validity, you can run:
``` console
cardano-signer verify --cip88 \
	--data-file myCalidusRegistrationMetadata.json
```
```
true
```


## Contacts

* Telegram - @atada_stakepool<br>
* Twitter - [@ATADA_Stakepool](https://twitter.com/ATADA_Stakepool)<br>
* Discord - MartinLang \[ATADA, SPO Scripts\]#5306
* Email - stakepool@stakepool.at<br>
* Homepage - https://stakepool.at
