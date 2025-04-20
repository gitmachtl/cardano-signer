## Release Notes / Change-Logs

* **1.24.1**

  #### CIP8/30 Updates

  - The CIP8/30 verification function now handles all set keys in the `protected header`. In the past the `protected header` was rebuilt for internal verification using only the `alg (map 1)` and `address` key entry.<br>Which could have caused an issue if Signature-Generators add additional keys in the `protected header`, like the optional `kid (map 4)` entry.<br>Now cardano-signer handles the header as it is and only replaces entries in the address and kid keys if an optional verification address is provided.
  - The *protected header map* is now also included in the `--json-extended` output for the `verify cip-8/30` command if you set the `--include-maps` flag.
    

* **1.24.0**

   #### Calidus Pool-Key updates

   - A new path shortcut `--path calidus` was added to the `keygen` function
   - Using the new calidus path also switches the output description of skey/vkey files to be `Calidus Pool Signing Key` and `Calidus Pool Verification Key`
   - Using the new calidus path also outputs the new `Calidus-ID` in hex and bech format with the `--json-extended` flag
   - The `sign --cip88` function to generate Calidus Key registration data now also outputs the new `Calidus-ID` in hex and bech format. In addition it also outputs the `Pool-ID` in bech format.
   - The `verify --cip88` function to verify Calidus Key registration data now also outputs the new `Calidus-ID` in hex and bech format. In addition it also outputs the `Pool-ID` in bech format.

   #### Other updates

   - A new internal function was created to convert maps in to json format, this is simplifying various inputs and output in the future
   - The key7 entry for the CIP88v2 format was renamed from `update-key` to `calidus-key`

* **1.23.0**
  
  #### NEW FUNCTION - Sign/Verify Calidus Pool-Key registration metadata (CIP88v2)

   - Generating of new Calidus Pool-Key registration metadata is now possible via the `sign --cip88` method<br>
     The data can be generated in human readable JSON format, or as a binary CBOR file. Both can directly be used in a transaction on the blockchain.
   - Verification of Calidus Pool-Key registration metadata is now possible via the `verify --cip88` method<br>
     The data for verification can be provided as JSON-File, JSON-Plaintext or as a CBOR-HexString

  #### Other Changes
  
    - Cardano-Signer is now using the cardano-serialization-lib version 14.1.1

* **1.22.0**
  - Verification of signatures in `--cip100` mode now also supports both the `CIP-0030` & `CIP-0008` author wittnessAlgorithm
  - Signing a jsonld file in `--cip100` mode with `ed25519` author signatures now also rechecks existing `CIP-0030/CIP-0008` signatures
  - Verification of a `--cip100` document now also returns the `fileHash` -> `anchorHash` of the document in the `--json` and `--json-extended` output format
  - Generating keys via the `keygen` and a set derivation path now also returns the `rootKey` in the `--json-extended` output-mode format
  - Verification of `CIP-0008` structures was moved into its own subfunction, so it can be reused within other functions
  - Upgraded to CSL v14.1.0

* **1.20.1**
  #### CIP100 Verification and Canonize 
    - Bugfix: Corrected a bug where doublequotes that are already escaped in the body content to form the canonized body array were escaped again.

* **1.20.0**
  #### NEW FUNCTION - Derive keys from Hardware-Wallet mnemonics
     - Two new flags have been added to the `keygen` mode:
		- `--ledger` let you derive your keys in Ledger-Hardware-Wallet type format
		- `--trezor` let you derive your keys in Trezor-Hardware-Wallet type format
  
  This new function allows to recover keys from a Hardware-Wallet as pure CLI-Keys.
  
  #### UPDATE/CHANGES:
     - The preset path `--path pool` has been added to the `keygen` mode, to directly derive Cardano-Pool Cold-Keys
	 - The `path` entry in the `--json-extended` output for the `keygen` mode was renamed into `derivationPath` (breaking!)
	 - A new entry was added in the `--json-extended` output for the `keygen` mode -> `derivationType`, which can be `icarus`, `ledger` or `trezor`
	 - If keys are derived for `--path drep` or `--path pool`, the output now also contains the corresponding DRep-ID/Pool-ID.

* **1.19.0**
  #### NEW FUNCTION - Adding authors signatures for CIP100 JSONLD metadata
     - A new function is now available via the 'sign --cip100' parameter. Its now possible to add authors entries (Name + Signature) with a single command using cardano-signer
  #### UPDATE/CHANGES:
     - cardano-signer is now compatible with CIP129 standard for drep, committee-cold and committee-hot bech strings. this works now for all functions that allow a '--address' parameter.
     - CIP 8/30 DataSign:
       - you can now directly also use governance bech-ids for the '--address' parameter like 'drep1xxx'
     - CIP 100 - Governance:
       - the canonize&hash command 'hash' introduced in version 1.17 was renamed to 'canonize'. change was made to avoid confusion, because this command is to output the hash of the canonized body, not the file-hash.
       - output fields of the 'canonize' and 'verify' function changed 'hash' is now 'canonizedHash', 'canonized' is now 'canonizedBody'
       - in addition to the existing checks in the 'verify' function, cardano-signer now also checks for duplicated public-key entries in the authors array of the input jsonld file

* **1.18.0**
  #### General
     - verify governance metadata following CIP-100, CIP-108, CIP-119 standard via the new `verify --cip100` option

* **1.17.0**
  #### General
     - Now using NODE.JS v18
     - Updated all dependencies to the latest versions

  #### New Hash mode to Canonize & Hash Governance Metadata
     - canonize & hash governance metadata following CIP-100, CIP-108, CIP-119 standard via the new `canonize --cip100` option

* **1.16.1**
  #### Catalyst Vote Key Generation CIP36
    - Bugfix: The description field of the generated *.vkey file was corrected to be 'Catalyst Vote Verification Key'

* **1.16.0**
  #### Signing & Verification in CIP-030/008 mode
    - Added a new flag `--nohashcheck` for the signing and verification in CIP030/008 format. Using this flag will tell cardano-signer to not perform a check of the hash in the address-field against the public-key during the verification process. And additionally it can disable the address/hash check in the signing process too.

* **1.15.1**
  #### General
	- small bugfix, parameters `help`, `usage`, `version` throwing an "unknown" error


* **1.15.0**
  #### New constitutional-commitee-member cold-key generation mode:
  	- generate conway cc-cold keys via the path `--path cc-cold` or
  	- generate conway cc-cold keys from the derivation path "1852'/1815'/acc'/4/idx'
  	- generate conway cc-cold keys from mnemonics or let cardano-signer generate new mnemonics for you

  #### New constitutional-commitee-member hot-key generation mode:
  	- generate conway cc-hot keys via the path `--path cc-hot` or
  	- generate conway cc-hot keys from the derivation path "1852'/1815'/acc'/5/idx'
  	- generate conway cc-hot keys from mnemonics or let cardano-signer generate new mnemonics for you

  #### General
  	- some corrections on extended verification key outputs
  	- an unknown parameter now throws an error. before, optional parameters with a typo were simply ignored
  	- general code cleanup, typos, etc.

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
