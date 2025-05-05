//define name and version
const appname = "cardano-signer"
const version = "1.24.2"

//external dependencies
const CardanoWasm = require("@emurgo/cardano-serialization-lib-nodejs")
const cbor = require("cbor"); //decode and encode cbor
const bech32 = require("bech32").bech32;  //used, because the CardanoWasm does not support the decoding of general bech strings for the public/private key
const fs = require("fs"); //filesystem io
const blakejs = require('blakejs'); //alternative blake2 implementation
const base64url = require('base64url'); //used for the CIP-8/CIP-30 user facing signedMessage string "cms_..."
const fnv32 = require('fnv32'); //used for CIP-8/CIP-30 checksum generation (fnv32a -> fnv32.fnv_1a) for the user facing signedMessage string "cms_..."
const bip39 = require('bip39'); //used for mnemonics operations
const crypto = require('crypto'); //used for crypto functions like entropy generation
const jsonld = require('jsonld'); //used for canonizing json data (governance CIP-0100 metadata)

//set the options for the command-line arguments. needed so that arguments like data-hex="001122" are not parsed as numbers
const parse_options = {
	string: ['secret-key', 'public-key', 'signature', 'address', 'rewards-address', 'payment-address', 'vote-public-key', 'calidus-public-key', 'data', 'data-hex', 'data-file', 'out-file', 'out-cbor', 'out-skey', 'out-vkey', 'out-canonized', 'cose-sign1', 'cose-key', 'mnemonics', 'path', 'testnet-magic', 'mainnet', 'author-name', 'passphrase'],
	boolean: ['help', 'version', 'usage', 'json', 'json-extended', 'cip8', 'cip30', 'cip36', 'cip88', 'cip100', 'deregister', 'jcli', 'bech', 'hashed', 'nopayload', 'vkey-extended', 'nohashcheck', 'replace', 'ledger', 'trezor', 'include-maps'], //all booleans are set to false per default
	//adding some aliases so users can also use variants of the original parameters. for example using --signing-key instead of --secret-key
	alias: { 'deregister': 'deregistration', 'cip36': 'cip-36', 'cip8': 'cip-8', 'cip30': 'cip-30', 'cip100': 'cip-100', 'secret-key': 'signing-key', 'public-key': 'verification-key', 'rewards-address': 'reward-address', 'data': 'data-text', 'jcli' : 'bech', 'mnemonic': 'mnemonics', 'vkey-extended': 'with-chain-code' },
	unknown: function(unknownParameter) {
			const numberParams = ['nonce', 'vote-weight', 'vote-purpose']; //these are parameter which specifies numbers, so they are not in the lists above, we only throw an error if the unknownParameter is not in this list
			if ( ! numberParams.includes(unknownParameter.substring(2).toLowerCase()) ) { //throw an error if given parameterName is not in any of the lists above
				process.stderr.write(`Error: Unknown parameter '${unknownParameter}'`);
				if ( ! unknownParameter.startsWith('--') ) { process.stderr.write(` - parameters must start with a double hypen like --secret-key`); }
				process.stderr.write(`\n`);
				process.exit(1);
				}
			}
};
const args = require('minimist')(process.argv.slice(3),parse_options); //slice(3) because we always have the workMode like 'keygen,sign,verify' at pos 2, so we start to look for arguments at pos 3

//various constants
const regExpHex = /^[0-9a-fA-F]+$/;
const regExpHexWith0x = /^(0x)?[0-9a-fA-F]+$/;
const regExpPath = /^[0-9]+H\/[0-9]+H\/[0-9]+H(\/[0-9]+H?){0,2}$/;  //path: first three elements must always be hardened, max. 5 elements
const regExpIntNumber = /^-?[0-9]+$/; //matches positive and optional negative integer numbers

//catch all exceptions that are not catched via try
process.on('uncaughtException', function (error) {
    console.error(`${error}`); process.exit(1);
});

function showUsage(topic, exit = true){
//FontColors
const Reset = "\x1b[0m"; const Bright = "\x1b[1m"; const Dim = "\x1b[2m"; const Underscore = "\x1b[4m"; const Blink = "\x1b[5m"; const Reverse = "\x1b[7m"; const Hidden = "\x1b[8m"
const FgBlack = "\x1b[30m"; const FgRed = "\x1b[31m"; const FgGreen = "\x1b[32m"; const FgYellow = "\x1b[33m"; const FgBlue = "\x1b[34m"; const FgMagenta = "\x1b[35m"; const FgCyan = "\x1b[36m"; const FgWhite = "\x1b[37m"

switch (topic) {

	case 'sign':
	        console.log(``)
	        console.log(`${Bright}${Underscore}Sign a hex/text-string or a binary-file:${Reset}`)
	        console.log(``)
	        console.log(`   Syntax: ${Bright}${appname} ${FgGreen}sign${Reset}`);
		console.log(`   Params: ${FgGreen}--data-hex${Reset} "<hex>" | ${FgGreen}--data${Reset} "<text>" | ${FgGreen}--data-file${Reset} "<path_to_file>"`);
		console.log(`								${Dim}data/payload/file to sign in hex-, text- or binary-file-format${Reset}`);
		console.log(`           ${FgGreen}--secret-key${Reset} "<path_to_file>|<hex>|<bech>"		${Dim}path to a signing-key-file or a direct signing hex/bech-key string${Reset}`);
		console.log(`           [${FgGreen}--address${Reset} "<path_to_file>|<hex>|<bech>"]		${Dim}optional address check against the signing-key (address-file or a direct bech/hex format)${Reset}`);
		console.log(`           [${FgGreen}--json${Reset} |${FgGreen} --json-extended${Reset}]				${Dim}optional flag to generate output in json/json-extended format${Reset}`);
		console.log(`           [${FgGreen}--jcli${Reset} |${FgGreen} --bech${Reset}]					${Dim}optional flag to generate signature & publicKey in jcli compatible bech-format${Reset}`);
		console.log(`           [${FgGreen}--out-file${Reset} "<path_to_file>"]			${Dim}path to an output file, default: standard-output${Reset}`);
	        console.log(`   Output: ${FgCyan}"signature + publicKey"${Reset} or ${FgCyan}JSON-Format${Reset}		${Dim}default: hex-format${Reset}`);
	        console.log(``)
		break;

	case 'sign-cip8':
	case 'sign-cip30':
	        console.log(``)
	        console.log(`${Bright}${Underscore}Sign a payload in CIP-8 / CIP-30 mode:${Reset} (COSE_Sign1 only currently)`)
	        console.log(``)
	        console.log(`   Syntax: ${Bright}${appname} ${FgGreen}sign --cip8${Reset}`);
	        console.log(`           ${Bright}${appname} ${FgGreen}sign --cip30${Reset}`);
		console.log(`   Params: ${FgGreen}--data-hex${Reset} "<hex>" | ${FgGreen}--data${Reset} "<text>" | ${FgGreen}--data-file${Reset} "<path_to_file>"${Reset}`);
		console.log(`								${Dim}data/payload/file to sign in hex-, text- or binary-file-format${Reset}`);
		console.log(`           ${FgGreen}--secret-key${Reset} "<path_to_file>|<hex>|<bech>"		${Dim}path to a signing-key-file or a direct signing hex/bech-key string${Reset}`);
		console.log(`           ${FgGreen}--address${Reset} "<path_to_file>|<hex>|<bech>"		${Dim}path to an address-file or a direct bech/hex format 'stake1..., stake_test1..., addr1...'${Reset}`);
		console.log(`           [${FgGreen}--nohashcheck${Reset}]					${Dim}optional flag to not perform a check that the public-key belongs to the address/hash${Reset}`);
		console.log(`           [${FgGreen}--hashed${Reset}]						${Dim}optional flag to hash the payload given via the 'data' parameters${Reset}`);
		console.log(`           [${FgGreen}--nopayload${Reset}]					${Dim}optional flag to exclude the payload from the COSE_Sign1 signature, default: included${Reset}`);
		console.log(`           [${FgGreen}--testnet-magic [xxx]${Reset}]				${Dim}optional flag to switch the address check to testnet-addresses, default: mainnet${Reset}`);
		console.log(`           [${FgGreen}--json${Reset} |${FgGreen} --json-extended${Reset}]				${Dim}optional flag to generate output in json/json-extended format${Reset}`);
		console.log(`           [${FgGreen}--out-file${Reset} "<path_to_file>"]			${Dim}path to an output file, default: standard-output${Reset}`);
	        console.log(`   Output: ${FgCyan}"COSE_Sign1 + COSE_Key"${Reset} or ${FgCyan}JSON-Format${Reset}`);
	        console.log(``)
		break;

	case 'sign-cip36':
	case 'sign-cip36-deregister':
	        console.log(``)
	        console.log(`${Bright}${Underscore}Sign a catalyst registration/delegation or deregistration in CIP-36 mode:${Reset}`)
	        console.log(``)
	        console.log(`   Syntax: ${Bright}${appname} ${FgGreen}sign --cip36${Reset}`);
		console.log(`   Params: [${FgGreen}--vote-public-key${Reset} "<path_to_file>|<hex>|<bech>"	${Dim}public-key-file(s) or public hex/bech-key string(s) to delegate the votingpower to (single or multiple)${Reset}`);
		console.log(`           ${FgGreen}--vote-weight${Reset} <unsigned_int>]			${Dim}relative weight of each delegated votingpower, default: 100% for a single delegation${Reset}`);
		console.log(`           ${FgGreen}--secret-key${Reset} "<path_to_file>|<hex>|<bech>"		${Dim}signing-key-file or a direct signing hex/bech-key string of the stake key (votingpower)${Reset}`);
		console.log(`           ${FgGreen}--payment-address${Reset} "<path_to_file>|<hex>|<bech>"	${Dim}rewards payout address (address-file or a direct bech/hex format 'addr1..., addr_test1...')${Reset}`);
		console.log(`           [${FgGreen}--nonce${Reset} <unsigned_int>]				${Dim}optional nonce value, if not provided the mainnet-slotHeight calculated from current machine-time will be used${Reset}`);
		console.log(`           [${FgGreen}--vote-purpose${Reset} <unsigned_int>]			${Dim}optional parameter (unsigned int), default: 0 (catalyst)${Reset}`);
		console.log(`           [${FgGreen}--deregister${Reset}]					${Dim}optional flag to generate a deregistration (no --vote-public-key/--vote-weight/--payment-address needed${Reset}`);
		console.log(`           [${FgGreen}--testnet-magic [xxx]${Reset}]				${Dim}optional flag to switch the address check to testnet-addresses, default: mainnet${Reset}`);
		console.log(`           [${FgGreen}--json${Reset} |${FgGreen} --json-extended${Reset}]				${Dim}optional flag to generate output in json/json-extended format, default: cborHex(text)${Reset}`);
		console.log(`           [${FgGreen}--out-file${Reset} "<path_to_file>"]			${Dim}path to an output file, default: standard-output${Reset}`);
		console.log(`           [${FgGreen}--out-cbor${Reset} "<path_to_file>"]			${Dim}path to write a binary metadata.cbor file to${Reset}`);
	        console.log(`   Output: ${FgCyan}Registration-Metadata in JSON-, cborHex-, cborBinary-Format${Reset}`);
	        console.log(``)
		break;

	case 'sign-cip88':
	        console.log(``)
	        console.log(`${Bright}${Underscore}Sign a Calidus-Pool-PublicKey registration with a Pool-Cold-Key in CIP-88 mode:${Reset}`)
	        console.log(``)
	        console.log(`   Syntax: ${Bright}${appname} ${FgGreen}sign --cip88${Reset}`);
		console.log(`   Params: ${FgGreen}--calidus-public-key${Reset} "<path_to_file>|<hex>|<bech>"	${Dim}public-key-file or public hex/bech-key string to use as the new calidus-key${Reset}`);
		console.log(`           ${FgGreen}--secret-key${Reset} "<path_to_file>|<hex>|<bech>"		${Dim}signing-key-file or a direct signing hex/bech-key string of the stakepool${Reset}`);
		console.log(`           [${FgGreen}--nonce${Reset} <unsigned_int>]				${Dim}optional nonce value, if not provided the mainnet-slotHeight calculated from current machine-time will be used${Reset}`);
		console.log(`           [${FgGreen}--json${Reset} |${FgGreen} --json-extended${Reset}]				${Dim}optional flag to generate output in json/json-extended format, default: cborHex(text)${Reset}`);
		console.log(`           [${FgGreen}--out-file${Reset} "<path_to_file>"]			${Dim}path to an output file, default: standard-output${Reset}`);
		console.log(`           [${FgGreen}--out-cbor${Reset} "<path_to_file>"]			${Dim}path to write a binary metadata.cbor file to${Reset}`);
	        console.log(`   Output: ${FgCyan}Registration-Metadata in JSON-, cborHex-, cborBinary-Format${Reset}`);
	        console.log(``)
		break;

	case 'sign-cip100':
	        console.log(``)
	        console.log(`${Bright}${Underscore}Sign a governance JSON-LD metadata file with a Secret-Key (add authors, ed25519 algorithm):${Reset}`)
	        console.log(``)
	        console.log(`   Syntax: ${Bright}${appname} ${FgGreen}sign --cip100${Reset}`);
		console.log(`   Params: ${FgGreen}--data${Reset} "<jsonld-text>" | ${FgGreen}--data-file${Reset} "<path_to_jsonld_file>"${Reset}`);
		console.log(`								${Dim}data or file in jsonld format to verify${Reset}`);
		console.log(`           ${FgGreen}--secret-key${Reset} "<path_to_file>|<hex>|<bech>"		${Dim}path to a signing-key-file or a direct signing hex/bech-key string${Reset}`);
		console.log(`           ${FgGreen}--author-name${Reset} "<name-of-signing-author>"		${Dim}name of the signing author f.e. "John Doe"${Reset}`);
		console.log(`           [${FgGreen}--replace${Reset}]						${Dim}optional flag to replace the authors entry with the same public-key${Reset}`);
		console.log(`           [${FgGreen}--out-file${Reset} "<path_to_file>"]			${Dim}path to an output file, default: standard-output${Reset}`);
	        console.log(`   Output: ${FgCyan}"Signed JSON-LD Content"${Reset} or ${FgCyan}"JSON-HashInfo if --out-file is used"${Reset}`);
	        console.log(``)
		break;

	case 'verify':
	        console.log(``)
	        console.log(`${Bright}${Underscore}Verify a hex/text-string or a binary-file via signature + publicKey:${Reset}`)
	        console.log(``)
	        console.log(`   Syntax: ${Bright}${appname} ${FgGreen}verify${Reset}`);
		console.log(`   Params: ${FgGreen}--data-hex${Reset} "<hex>" | ${FgGreen}--data${Reset} "<text>" | ${FgGreen}--data-file${Reset} "<path_to_file>"${Reset}`);
		console.log(`								${Dim}data/payload/file to verify in hex-, text- or binary-file-format${Reset}`);
		console.log(`           ${FgGreen}--signature${Reset} "<hex>|<bech>"				${Dim}signature in hex- or bech-format${Reset}`);
		console.log(`           ${FgGreen}--public-key${Reset} "<path_to_file>|<hex>|<bech>"		${Dim}path to a public-key-file or a direct public hex/bech-key string${Reset}`);
		console.log(`           [${FgGreen}--address${Reset} "<path_to_file>|<hex>|<bech>"]		${Dim}optional address check against the public-key (address-file or a direct bech/hex format)${Reset}`);
		console.log(`           [${FgGreen}--json${Reset} |${FgGreen} --json-extended${Reset}]				${Dim}optional flag to generate output in json/json-extended format${Reset}`);
		console.log(`           [${FgGreen}--out-file${Reset} "<path_to_file>"]			${Dim}path to an output file, default: standard-output${Reset}`);
	        console.log(`   Output: ${FgCyan}"true/false" (exitcode 0/1)${Reset} or ${FgCyan}JSON-Format${Reset}`)
	        console.log(``)
		break;

	case 'verify-cip8':
	case 'verify-cip30':
	        console.log(``)
	        console.log(`${Bright}${Underscore}Verify a CIP-8 / CIP-30 payload:${Reset} (COSE_Sign1 only currently)`)
	        console.log(``)
	        console.log(`   Syntax: ${Bright}${appname} ${FgGreen}verify --cip8${Reset}`);
	        console.log(`           ${Bright}${appname} ${FgGreen}verify --cip30${Reset}`);
		console.log(`   Params: ${FgGreen}--cose-sign1${Reset} "<hex>"					${Dim}COSE_Sign1 signature in cbor-hex-format${Reset}`);
		console.log(`           ${FgGreen}--cose-key${Reset} "<hex>"					${Dim}COSE_Key containing the public-key in cbor-hex-format${Reset}`);
		console.log(`           [${FgGreen}--data-hex${Reset} "<hex>" | ${FgGreen}--data${Reset} "<text>" | ${FgGreen}--data-file${Reset} "<path_to_file>"${Reset}]`);
		console.log(`								${Dim}optional data/payload/file if not present in the COSE_Sign1 signature${Reset}`);
		console.log(`           [${FgGreen}--address${Reset} "<path_to_file>|<hex>|<bech>"]		${Dim}optional signing-address to do the verification with${Reset}`);
		console.log(`           [${FgGreen}--nohashcheck${Reset}]					${Dim}optional flag to not perform a check that the public-key belongs to the address/hash${Reset}`);
		console.log(`           [${FgGreen}--include-maps${Reset}]					${Dim}optional flag to include the COSE maps in the json-extended output${Reset}`);
		console.log(`           [${FgGreen}--json${Reset} |${FgGreen} --json-extended${Reset}]				${Dim}optional flag to generate output in json/json-extended format${Reset}`);
		console.log(`           [${FgGreen}--out-file${Reset} "<path_to_file>"]			${Dim}path to an output file, default: standard-output${Reset}`);
	        console.log(`   Output: ${FgCyan}"true/false" (exitcode 0/1)${Reset} or ${FgCyan}JSON-Format${Reset}`)
	        console.log(``)
		break;

	case 'verify-cip88':
	        console.log(``)
	        console.log(`${Bright}${Underscore}Verify CIP-88 Calidus-Pool-PublicKey registration-data:${Reset}`)
	        console.log(``)
	        console.log(`   Syntax: ${Bright}${appname} ${FgGreen}verify --cip88${Reset}`);
		console.log(`   Params: ${FgGreen}--data${Reset} "<json-metadata>" |				${Dim}data to verify as json text${Reset}`);
		console.log(`           ${FgGreen}--data-file${Reset} "<path_to_file>" |			${Dim}data to verify as json file${Reset}`);
		console.log(`           ${FgGreen}--data-hex${Reset} "<hex>"					${Dim}data to verify as cbor-hex-format${Reset}`);
		console.log(`           [${FgGreen}--json${Reset} |${FgGreen} --json-extended${Reset}]				${Dim}optional flag to generate output in json/json-extended format${Reset}`);
		console.log(`           [${FgGreen}--out-file${Reset} "<path_to_file>"]			${Dim}path to an output file, default: standard-output${Reset}`);
	        console.log(`   Output: ${FgCyan}"true/false"${Reset} or ${FgCyan}JSON-Format${Reset}`);
	        console.log(``)
		break;

	case 'verify-cip100':
	        console.log(``)
	        console.log(`${Bright}${Underscore}Verify Signatures in CIP-100/108/119/136 governance JSON-LD metadata:${Reset}`)
	        console.log(``)
	        console.log(`   Syntax: ${Bright}${appname} ${FgGreen}verify --cip100${Reset}`);
		console.log(`   Params: ${FgGreen}--data${Reset} "<jsonld-text>" | ${FgGreen}--data-file${Reset} "<path_to_jsonld_file>"${Reset}`);
		console.log(`								${Dim}data or file in jsonld format to verify${Reset}`);
		console.log(`           [${FgGreen}--json${Reset} |${FgGreen} --json-extended${Reset}]				${Dim}optional flag to generate output in json/json-extended format${Reset}`);
		console.log(`           [${FgGreen}--out-file${Reset} "<path_to_file>"]			${Dim}path to an output file, default: standard-output${Reset}`);
	        console.log(`   Output: ${FgCyan}"true/false"${Reset} or ${FgCyan}JSON-Format${Reset}`);
	        console.log(``)
		break;

	case 'keygen':
	case 'keygen-cip36':
	case 'keygen-ledger':
	case 'keygen-trezor':
	        console.log(``)
	        console.log(`${Bright}${Underscore}Generate Cardano ed25519/ed25519-extended keys:${Reset}`)
	        console.log(``)
	        console.log(`   Syntax: ${Bright}${appname} ${FgGreen}keygen${Reset}`);
		console.log(`   Params: [${FgGreen}--path${Reset} "<derivationpath>"]				${Dim}optional derivation path in the format like "1852H/1815H/0H/0/0" or "1852'/1815'/0'/0/0"${Reset}`);
		console.log(`								${Dim}or predefined names: --path payment, --path stake, --path cip36, --path drep, --path cc-cold,${Reset}`);
		console.log(`								${Dim}                     --path cc-hot, --path pool, --path calidus${Reset}`);
		console.log(`           [${FgGreen}--mnemonics${Reset} "word1 word2 ... word24"]		${Dim}optional mnemonic words to derive the key from (separate via space)${Reset}`);
		console.log(`           [${FgGreen}--passphrase${Reset} "passphrase"] 				${Dim}optional passphrase for --ledger or --trezor derivation method${Reset}`);
		console.log(`           [${FgGreen}--ledger | --trezor${Reset}] 				${Dim}optional flag to set the derivation type to "Ledger" or "Trezor" hardware wallet${Reset}`);
		console.log(`           [${FgGreen}--cip36${Reset}] 						${Dim}optional flag to generate CIP36 conform vote keys (also using path 1694H/1815H/0H/0/0)${Reset}`);
		console.log(`           [${FgGreen}--vote-purpose${Reset} <unsigned_int>]			${Dim}optional vote-purpose (unsigned int) together with --cip36 flag, default: 0 (Catalyst)${Reset}`);
		console.log(`           [${FgGreen}--vkey-extended${Reset}] 					${Dim}optional flag to generate a 64byte publicKey with chain code${Reset}`);
		console.log(`           [${FgGreen}--json${Reset} |${FgGreen} --json-extended${Reset}]				${Dim}optional flag to generate output in json/json-extended format${Reset}`);
		console.log(`           [${FgGreen}--out-file${Reset} "<path_to_file>"]			${Dim}path to an output file, default: standard-output${Reset}`);
		console.log(`           [${FgGreen}--out-skey${Reset} "<path_to_skey_file>"]			${Dim}path to an output skey-file${Reset}`);
		console.log(`           [${FgGreen}--out-vkey${Reset} "<path_to_vkey_file>"]			${Dim}path to an output vkey-file${Reset}`);
	        console.log(`   Output: ${FgCyan}"secretKey + publicKey"${Reset} or ${FgCyan}JSON-Format${Reset}		${Dim}default: hex-format${Reset}`);
	        console.log(``)
		break;

	case 'canonize':
	case 'canonize-cip100':
	        console.log(``)
	        console.log(`${Bright}${Underscore}Canonize&Hash the governance JSON-LD body metadata for author-signatures:${Reset} (CIP-100)`)
	        console.log(``)
	        console.log(`   Syntax: ${Bright}${appname} ${FgGreen}canonize --cip100${Reset}`);
		console.log(`   Params: ${FgGreen}--data${Reset} "<jsonld-text>" | ${FgGreen}--data-file${Reset} "<path_to_jsonld_file>"${Reset}`);
		console.log(`								${Dim}data or file in jsonld format to canonize and hash${Reset}`);
		console.log(`           [${FgGreen}--json${Reset} |${FgGreen} --json-extended${Reset}]				${Dim}optional flag to generate output in json/json-extended format${Reset}`);
		console.log(`           [${FgGreen}--out-canonized${Reset} "<path_to_file>"]			${Dim}path to an output file for the canonized data${Reset}`);
		console.log(`           [${FgGreen}--out-file${Reset} "<path_to_file>"]			${Dim}path to an output file, default: standard-output${Reset}`);
	        console.log(`   Output: ${FgCyan}"HASH of canonized body"${Reset} or ${FgCyan}JSON-Format${Reset}		${FgRed}NOTE: This is NOT the anchor-url-hash!!!${Reset}`);
	        console.log(``)
		break;


	default:
		showUsage('sign',false);
		showUsage('sign-cip8',false)
		showUsage('sign-cip36',false)
		showUsage('sign-cip88',false)
		showUsage('sign-cip100',false)
		showUsage('verify',false)
		showUsage('verify-cip8',false)
		showUsage('verify-cip88',false)
		showUsage('verify-cip100',false)
		showUsage('keygen',false)
		showUsage('canonize-cip100',false)
		console.log(``)
		console.log(`${Dim}${Underscore}Info:${Reset}`);
		console.log(`   ${Dim}https://github.com/gitmachtl (Cardano SPO Scripts \/\/ ATADA Stakepools Austria)${Reset}`)
		console.log(``)


} //switch
if ( exit ) { process.exit(1); }
}


//function to count the words in a string
function wordCount(s) {
        return s.split(' ')
                .filter(function(n) { return n != '' })
                .length;
}

//trimString function to cut of leading or trailing white-spaces and newline chars
function trimString(s){
        s = s.replace(/(^\s*)|(\s*$)/gi,"");    //exclude start and end white-space
        s = s.replace(/\n /,"\n");              // exclude newline with a start spacing
        return s;
}

//Special trimString variant to also reduce spaces between words
function trimMnemonic(s){
        s = s.replace(/(^\s*)|(\s*$)/gi,"");    // exclude start and end white-space
        s = s.replace(/[ ]{2,}/gi," ");         // 2 or more space between words to 1
        s = s.replace(/\n /,"\n");              // exclude newline with a start spacing
        return s;
}

function readKey2hex(key,type,jsonSearchArray) { //reads a standard-cardano-skey/vkey-file-json, a direct hex entry or a bech-string  // returns a hexstring of the key

	//inputs:
	//	key -> string that points to a file or direct data
	//	type -> string 'secret' or 'public'
	//	jsonSearchArray -> defaults to ['Signing','ExtendedSigning'] for secret type and ['Verification','ExtendedVerification'] for public type.
	//			It can be used to filter for a specific type of json key. f.e. ['StakePoolSigning','StakePoolExtendedSigning']

	//returns:
	//	secretkey 32 or 64 bytes long (type = secret)
	//	publickey 32 bytes long (type = public)

	var key_hex = "";

	switch (type) {

		case "secret": //convert a secret key into a hex string, always returns the full privat-key-hex (extended or non-extended)

			// set the default searchstring for the type file in json key files
			if ( ! jsonSearchArray ) { jsonSearchArray = [ 'Signing', 'ExtendedSigning' ]; }

			// try to use the parameter as a filename for a cardano skey json with a cborHex entry
			try {
				const key_json = JSON.parse(fs.readFileSync(key,'utf8')); //parse the given key as a json file
//				const is_signing_key = key_json.type.toLowerCase().includes('signing') //boolean if the json contains the keyword 'signing' in the type field
				const is_signing_key = jsonSearchArray.some( element => key_json.type.toLowerCase().includes(element.toLowerCase()) ); //boolean if the json contains one of the keywords in the jsonSearchArray
				if ( ! is_signing_key ) { console.error(`Error: The file '${key}' is not a secret key json of type '${jsonSearchArray}'. Instead it is of type '` + key_json.type + `'`); process.exit(1); }
				key_hex = key_json.cborHex.substring(4).toLowerCase(); //cut off the leading "5820/5840" from the cborHex
				//check that the given key is a hex string
				if ( ! regExpHex.test(key_hex) ) { console.error(`Error: The secret key in file '${key}' entry 'cborHex' is not a valid hex string`); process.exit(1); }
				return key_hex;
			} catch (error) {}

			// try to use the parameter as a filename for a bech encoded string in it (typical keyfiles generated via jcli)
			try {
				const content = trimString(fs.readFileSync(key,'utf8')); //read the content of the given key from a file
				try { //try to load it as a bech secret key
					key_hex = Buffer.from(bech32.fromWords(bech32.decode(content,1000).words)).toString('hex');
				 } catch (error) { console.error(`Error: The content in file '${key}' is not a valid bech secret key`); process.exit(1); }
				return key_hex;
			} catch (error) {}

			// try to use the parameter as a bech encoded string
			try {
				key_hex = Buffer.from(bech32.fromWords(bech32.decode(key,1000).words)).toString('hex');
				return key_hex;
			} catch (error) {}

			// try to use the parameter as a direct hex string
			key_hex = trimString(key.toLowerCase());
			//check that the given key is a hex string
			if ( ! regExpHex.test(key) ) { console.error(`Error: Provided secret key '${key}' is not a valid secret key. Or not a hex string, bech encoded key, or the file is missing`); process.exit(1); }
			return key_hex;
			break;


		case "public": //convert a public key into a hex string, always return a non-extended public-key-hex

			// set the default searchstring for the type file in json key files
			if ( ! jsonSearchArray ) { jsonSearchArray = [ 'Verification', 'ExtendedVerification' ]; }

			// try to use the parameter as a filename for a cardano vkey json with a cborHex entry
			try {
				const key_json = JSON.parse(fs.readFileSync(key,'utf8')); //parse the given key as a json file
//				const is_verification_key = key_json.type.toLowerCase().includes('verification') //boolean if the json contains the keyword 'verification' in the type field
				const is_verification_key = jsonSearchArray.some( element => key_json.type.toLowerCase().includes(element.toLowerCase()) ); //boolean if the json contains one of the keywords in the jsonSearchArray
				if ( ! is_verification_key ) { console.error(`Error: The file '${key}' is not a public key json of type '${jsonSearchArray}'. Instead it is of type '` + key_json.type + `'`); process.exit(1); }
				key_hex = key_json.cborHex.substring(4).toLowerCase(); //cut off the leading "5820/5840" from the cborHex
				//check that the given key is a hex string
				if ( ! regExpHex.test(key_hex) ) { console.error(`Error: The public key in file '${key}' entry 'cborHex' is not a valid hex string`); process.exit(1); }
				return key_hex.substring(0,64); //return a non-extended public key
			} catch (error) {}

			// try to use the parameter as a filename for a bech encoded string in it (typical keyfiles generated via jcli)
			try {
				const content = trimString(fs.readFileSync(key,'utf8')); //read the content of the given key from a file
				try { //try to load it as a bech public key
					key_hex = Buffer.from(bech32.fromWords(bech32.decode(content,1000).words)).toString('hex');
				 } catch (error) { console.error(`Error: The content in file '${key}' is not a valid bech public key`); process.exit(1); }
				return key_hex.substring(0,64); //return a non-extended public key
			} catch (error) {}

			// try to use the parameter as a bech encoded string
			try {
				key_hex = Buffer.from(bech32.fromWords(bech32.decode(key,1000).words)).toString('hex');
				return key_hex.substring(0,64); //return a non-extended public key
			} catch (error) {}

			// try to use the parameter as a direct hex string
			key_hex = trimString(key.toLowerCase());
			//check that the given key is a hex string
			if ( ! regExpHex.test(key) ) { console.error(`Error: Provided public key '${key}' is not a valid hex string, bech encoded key, or the file is missing`); process.exit(1); }
			else if ( key_hex.length < 64 ) { console.error(`Error: Provided hex public key '${key}' is too short`); process.exit(1); }
			return key_hex.substring(0,64); //return a non-extended public key
			break;

	} //switch (type)

}

function readAddr2hex(addr, publicKey) { //reads a cardano address from a file (containing a bech address), a direct hex entry or a bech-string  // returns a hexstring of the address + type + network

	//inputs:
	//	addr -> string that points to a file or direct data
	//	publicKey (optional) -> a hex encoded publicKey. if provided, a check will occure if the key belongs to the publicKey. returned in the 'matchPubKey' value

	//returns: Object with values
	//	hex -> hex string of the address
	//	type -> addresstype (payment-base, payment-enterprise, stake)
	//	network -> 'mainnet' or 'testnet'
	//	matchPubKey -> true or false
	let addr_hex;
	let addr_type = 'hash';
	let addr_network = 'unknown';
	let addr_matchPubKey = false;

	// first check, if the given address is an empty string, exit with an error
	if ( trimString(addr) == '' ) { console.error(`Error: The address value is empty`); process.exit(1); }

	// try to use the parameter as a filename for a bech encoded string in it (typical .addr files)
	try {  // outer try is needed to check if the file is present in first place
		const content = trimString(fs.readFileSync(addr,'utf8')); //read the content of the given addr from a file
		try { // inner try to check if the content is a bech address

			addr_hex = Buffer.from(bech32.fromWords(bech32.decode(content,1000).words)).toString('hex');
			//ok, no failure so far. lets check if we can figure out if its a governance bech
			if ( content.startsWith('drep') && addr_hex.length == 56 ) 	{ addr_type = 'drep'; }
			else if ( content.startsWith('drep_script') ) 			{ addr_type = 'drep script'; }
			else if ( content.startsWith('cc_cold') && addr_hex.length == 56 ) { addr_type = 'committee-cold'; }
			else if ( content.startsWith('cc_cold_script') )			{ addr_type = 'committee-cold script'; }
			else if ( content.startsWith('cc_hot') && addr_hex.length == 56 )	{ addr_type = 'committee-hot'; }
			else if ( content.startsWith('cc_hot_script') )			{ addr_type = 'committee-hot script'; }

		} catch (error) { console.error(`Error: The address in file '${addr}' is not a valid bech address`); process.exit(1); }
	} catch (error) {}

	// try to use the parameter as a bech encoded string
	if ( ! addr_hex ) {
		try {

			addr_hex = Buffer.from(bech32.fromWords(bech32.decode(addr,1000).words)).toString('hex'); //old (does not support drep1,cc_hot, etc prefixes) addr_hex = CardanoWasm.Address.from_bech32(content).to_hex();
			//ok, no failure so far. lets check if we can figure out if its a governance bech
			if ( addr.startsWith('drep') && addr_hex.length == 56 ) 	{ addr_type = 'drep'; }
			else if ( addr.startsWith('drep_script') ) 			{ addr_type = 'drep script'; }
			else if ( addr.startsWith('cc_cold') && addr_hex.length == 56 ) { addr_type = 'committee-cold'; }
			else if ( addr.startsWith('cc_cold_script') )			{ addr_type = 'committee-cold script'; }
			else if ( addr.startsWith('cc_hot') && addr_hex.length == 56 )	{ addr_type = 'committee-hot'; }
			else if ( addr.startsWith('cc_hot_script') )			{ addr_type = 'committee-hot script'; }

		} catch (error) {}
	}

	// try to use the parameter as a direct hex string
	if ( ! addr_hex ) {
		addr_hex = trimString(addr.toLowerCase());
		//check that the given key is a hex string
		if ( ! regExpHex.test(addr_hex) ) { console.error(`Error: Provided address '${addr}' is not a valid hex string, bech encoded address, or the file is missing`); process.exit(1); }
	}

	// we have a valid address in the addr_hex variable


        // check the address type if addr_hex is longer than 56 chars, otherwise its a simple hash
	if ( addr_hex.length > 56 && addr_type == 'hash' ) {

		hashcheck: {

			// check if there is a cip129 governance hash present (hash hex length 58 chars)
			if (addr_hex.length == 58) {
				switch (addr_hex.substring(0,2)) {
					case '02': addr_type = 'committee-hot cip129'; break hashcheck; break;
					case '03': addr_type = 'committee-hot script cip129'; break hashcheck; break;
					case '12': addr_type = 'committee-cold cip129'; break hashcheck; break;
					case '13': addr_type = 'committee-cold script cip129'; break hashcheck; break;
					case '22': addr_type = 'drep cip129'; break hashcheck; break;
					case '23': addr_type = 'drep script cip129'; break hashcheck; break;
					case 'a1': addr_type = 'calidus pool key'; break hashcheck; break;
				}
			}

			// check normal hashes
			// get the address type for information
			switch (addr_hex.substring(0,1)) {
				case '0': addr_type = 'payment base'; break;
				case '1': addr_type = 'script base'; break;
				case '2': addr_type = 'payment script'; break;
				case '3': addr_type = 'script script'; break;
				case '4': addr_type = 'payment pointer'; break;
				case '5': addr_type = 'script pointer'; break;
				case '6': addr_type = 'payment enterprise'; break;
				case '7': addr_type = 'script'; break;
				case 'e': addr_type = 'stake'; break;
				case 'f': addr_type = 'stake script'; break;
				default: addr_type = 'unknown';
			}

			// get the address network information
			switch (addr_hex.substring(1,2)) {
				case '0': addr_network = 'testnet'; break;
				case '1': addr_network = 'mainnet'; break;
				default: addr_network = 'unknown';
			}
		}

	}

	// optional check if the address matches the given publicKey
	if ( publicKey && addr_hex.includes(getHash(publicKey, 28)) ) { // set addr_matchPubKey to true if the address contain the pubKey hash
		addr_matchPubKey = true;
	}

	return {
		'addr': addr,
		'hex': addr_hex,
		'type': addr_type,
		'network': addr_network,
		'matchPubKey': addr_matchPubKey
	}

}


function getHash(content, digestLengthBytes = 32) { //hashes a given hex-string content with blake2b_xxx, digestLength is given via the digestLengthBytes parameter, key = null
    // if no digestLength is specified, use the default of 256bits/32bytes -> blake2b_256
    return blakejs.blake2bHex(Buffer.from(content,'hex'), null, digestLengthBytes)
}


// Some cryptographic helper functions especially for ledger and trezor derivation method
function generateIcarusMasterKey(entropy, passphrase) {
        const xprv = crypto.pbkdf2Sync(passphrase,entropy,4096,96,'sha512')
        xprv[0]  &= 0b1111_1000; // clear the lowest 3 bits
        xprv[31] &= 0b0001_1111; // clear the highest 3 bits  (actually its 'clear the highest bit, clear the 3rd highest bit. but as we also set the 2nd highest bit, we can do it all at once)
        xprv[31] |= 0b0100_0000; // set the 2nd highest bit
        return xprv;
}

function generateLedgerMasterKey(mnemonic, passphrase) {
        const masterSeed = crypto.pbkdf2Sync(mnemonic,"mnemonic" + passphrase,2048,64,'sha512')
        const message = new Uint8Array([1, ...masterSeed])  // mirror Adrestia's code bug "1"+seed
        const cc = crypto.createHmac('sha256',"ed25519 seed")
                .update(message)
                .digest()
	const tweakedHash = hmacRecursive(masterSeed)
        tweakedHash[0]  &= 0b1111_1000; // clear the lowest 3 bits
        tweakedHash[31] &= 0b0111_1111; // clear the highest bit
        tweakedHash[31] |= 0b0100_0000; // set the 2nd highest bit
        var xprv = new Uint8Array([...tweakedHash, ...cc])
        return xprv;
}

function hmacRecursive(message) {
        var hmac = crypto.createHmac('sha512',"ed25519 seed")
                .update(message)
                .digest()

        if (hmac[31] & 0b0010_0000) {
                return hmacRecursive(hmac);
        }
        return hmac;
}

function leftPad(str, padString, length) {
        while (str.length < length) {
                str = padString + str;
        }
        return str;
}

function binaryToByte(bin) {
        return parseInt(bin, 2);
}

function bytesToBinary(bytes) {
        return bytes.map((x) => leftPad(x.toString(2), '0', 8)).join('');
}

function deriveChecksumBits(entropyBuffer) {
        const ENT = entropyBuffer.length * 8;
        const CS = ENT / 32;
        const hash = crypto.createHash('sha256')
                .update(entropyBuffer)
                .digest();
        return bytesToBinary(Array.from(hash)).slice(0, CS);
}

// function to convert a json object (JSON.parse) into a Map, this also converts hex-strings into bytearrays/buffers
const jsToMap = (obj) => {
    switch (typeof obj) {
        case "object":
            if (Array.isArray(obj)) {
                for (let i = 0; i < obj.length; i++) {
                    obj[i] = jsToMap(obj[i]);
                }
                return obj;
            } else if (Buffer.isBuffer(obj)) {
                return obj;
            } else {
                const myMap = new Map();
                for (const [key, value] of Object.entries(obj)) {
			// check if key is a pos or neg integer number, if so, use the key as a number and not as a string
			if (regExpIntNumber.test(key)) { myMap.set(parseInt(key), jsToMap(value)) } else { myMap.set(key, jsToMap(value)); }
                }
                return myMap;
            }
        default:
            if (obj.match !== undefined) {
                return obj.match(regExpHexWith0x) ? Buffer.from(obj.replace('0x',''), 'hex') : obj;
            }
            return obj;
    }
}

const mapToJs = (obj) => {
	return JSON.stringify(obj, function (key, value) {
		if (value instanceof Map) { return Object.fromEntries(value) }
		else if (value instanceof Set) { const setArray = []; for( const item of value.values()){setArray.push(item)}; return setArray }
		else if (value == null) { return null }
		else if (value['type'] == 'Buffer') { return `0x${Buffer.from(value['data']).toString('hex')}` }
		return value
  })
}

// VERIFY CIP8/30 FUNCTION -> coded as a function so it can be reused within other functions
function verifyCIP8(workMode = "verify-cip8", calling_args = process.argv.slice(3)) { //default calling arguments are the same as calling the main process - can be modified by subfunctions

			var sub_args = require('minimist')(calling_args,parse_options);

			//get optional payload_data_hex to use in case there is no payload present in the COSE_Sign1 signature
			var data_hex = sub_args['data-hex'];
		        if ( typeof data_hex === 'string' ) { // a nullstring is also ok
				//data-hex is present, lets trim it, convert it to lowercase
			        var payload_data_hex = trimString(data_hex.toLowerCase());
				//check that the given data is a hex string, skip the test if its empty. a nullstring is ok
				if ( payload_data_hex != '' && ! regExpHex.test(payload_data_hex) ) { throw {'msg': `Data is not a valid hex string`}; }
			}


			if ( ! payload_data_hex ) { //no payload_data_hex present, lets try the data-file parameter
				var payload_data_file = sub_args['data-file'];
			        if ( typeof payload_data_file === 'string' && payload_data_file != '' ) {
					//data-file present lets read the file and store it hex encoded in payload_data_hex
						try {
							var payload_data_hex = fs.readFileSync(payload_data_file,null).toString('hex'); //reads the file as binary
						} catch (error) { throw {'msg': `Can't read data-file '${payload_data_file}'`}; }
				}
			}

			if ( ! payload_data_hex ) { //no payload_data_hex present, lets try the data (data-hex) parameter
				var payload_data = sub_args['data'];
			        if ( typeof payload_data === 'string' ) { // a nullstring is also ok
					//data parameter present, lets convert it to hex and store it in the payload_data_hex variable
					var payload_data_hex = Buffer.from(payload_data).toString('hex');
				}
			}

			//there might be a payload_data_hex preset now, or it is 'undefined' if not provided via the optional data parameters


			//get the COSE_Key to verify
			var COSE_Key_cbor_hex = sub_args['cose-key'];
		        if ( typeof COSE_Key_cbor_hex === 'undefined' || COSE_Key_cbor_hex === true ) { throw {'msg': `Missing COSE_Key parameter --cose-key`, 'showUsage': workMode}; }
			COSE_Key_cbor_hex = trimString(COSE_Key_cbor_hex.toLowerCase());

			//check that COSE_Key_cbor_hex is a valid hex string before passing it on to the cbor decoding
			if ( ! regExpHex.test(COSE_Key_cbor_hex) ) { throw {'msg': `COSE_Key is not a valid hex string`}; }

			//cbor decode the COSE_Key_cbor_hex into the COSE_Key_structure
			try {
				var COSE_Key_structure = cbor.decode(COSE_Key_cbor_hex)
			} catch (error) { throw {'msg': `Can't cbor decode the given COSE_Key signature (${error})`}; }

			//do a sanity check on the decoded COSE_Key_structure
			if ( ! COSE_Key_structure instanceof Map || COSE_Key_structure.size < 4 ) { throw {'msg': `COSE_Key is not valid. It must be a map with at least 4 entries: kty,alg,crv,x.`}; }
			else if ( COSE_Key_structure.get(1) != 1 ) { throw {'msg': `COSE_Key map label '1' (kty) is not '1' (OKP)`}; }
			else if ( COSE_Key_structure.get(3) != -8 ) { throw {'msg': `COSE_Key map label '3' (alg) is not '-8' (EdDSA)`}; }
			else if ( COSE_Key_structure.get(-1) != 6 ) { throw {'msg': `COSE_Key map label '-1' (crv) is not '6' (Ed25519)`}; }
			else if ( ! COSE_Key_structure.has(-2) ) { throw {'msg': `COSE_Key map label '-2' (public key) is missing`}; }

			//get the publickey
			var pubKey_buffer =  COSE_Key_structure.get(-2);
			if ( ! Buffer.isBuffer(pubKey_buffer) ) { throw {'msg': `PublicKey entry in the COSE_Key is not a bytearray`}; }
			var pubKey = pubKey_buffer.toString('hex')

			//load the publickey
			try {
			var publicKey = CardanoWasm.PublicKey.from_bytes(Buffer.from(pubKey,'hex'));
			} catch (error) { throw {'msg': `${error}`}; }

			//get the COSE_Sign1 signature to verify
			var COSE_Sign1_cbor_hex = sub_args['cose-sign1'];
		        if ( typeof COSE_Sign1_cbor_hex === 'undefined' || COSE_Sign1_cbor_hex === true ) { throw {'msg': `Missing COSE_Sign1 signature parameter --cose-sign1`, 'showUsage': workMode}; }
			COSE_Sign1_cbor_hex = trimString(COSE_Sign1_cbor_hex.toLowerCase());

			//check that COSE_Sign1_cbor_hex is a valid hex string before passing it on to the cbor decoding
			if ( ! regExpHex.test(COSE_Sign1_cbor_hex) ) { throw {'msg': `COSE_Sign1 is not a valid hex string`}; }

			//cbor decode the COSE_Sign1_cbor_hex into the COSE_Sign1_structure
			try {
				var COSE_Sign1_structure = cbor.decode(COSE_Sign1_cbor_hex)
			} catch (error) { throw {'msg': `Can't cbor decode the given COSE_Sign1 signature (${error})`}; }

			//do a sanity check on the decoded COSE_Sign1_structure
			if ( COSE_Sign1_structure instanceof Array == false || COSE_Sign1_structure.length != 4 ) { throw {'msg': `COSE_Sign1 is not a valid signature. It must be an array with 4 entries.`}; }

			//extract the content: protectedHeader, unprotectedHeader, payload, signature
			//
			// 1) protectedHeader

				var protectedHeader_buffer = COSE_Sign1_structure[0];
				if ( ! Buffer.isBuffer(protectedHeader_buffer) ) { throw {'msg': `Protected header is not a bytearray (serialized) cbor`}; }
				//cbor decode the protectedHeader_cbor_hex into protectedHeader
				try {
					var protectedHeader = cbor.decode(protectedHeader_buffer)
				} catch (error) { throw {'msg': `Can't cbor decode the protected header (${error})`}; }

				//extract the content and do a check on the map entries
				if ( ! protectedHeader.has(1) ) { throw {'msg': `Protected header map label '1' is missing`}; }
				else if ( protectedHeader.get(1) != -8 ) { throw {'msg': `Protected header map label '1' (alg) is not '-8' (EdDSA)`}; }
				else if ( ! protectedHeader.has('address') ) { throw {'msg': `Protected header map label 'address' is missing`}; }
				var sign_addr_buffer = protectedHeader.get('address');
				if ( ! Buffer.isBuffer(sign_addr_buffer) ) { throw {'msg': `Protected header map label 'address' invalid`}; }

				//if there is an optional address parameter present, use it instead of the one from the COSE_Sign1 signature
	                        var address = sub_args['address'];
	                        if ( typeof address === 'string' ) { //do the check if the parameter is provided
					//read the address from a file or direct hex/bech
				        sign_addr = readAddr2hex(address, pubKey);
		                        //check that the given address belongs to the pubKey
		                        if ( ( sub_args['nohashcheck'] === false ) && ! sign_addr.matchPubKey ) { //exit with an error if the address does not contain the pubKey hash
		                                throw {'msg': `The given ${sign_addr.type} address '${sign_addr.addr}' does not belong to the public key in the COSE_Key.`};
					}
					//replace the 'address' map in the protectedHeader with the given one
					protectedHeader.set('address',Buffer.from(sign_addr.hex,'hex'));
					//check if the optional kid (map4) "key-identifier" was also supplied in the protectedHeader. if so, also replace that entry
					if ( protectedHeader.has(4) ) { protectedHeader.set(4,Buffer.from(sign_addr.hex,'hex')); }
				} else {
					//read the sign_addr from the protectedHeader
				        sign_addr = readAddr2hex(sign_addr_buffer.toString('hex'), pubKey);
		                        //check that the address belongs to the pubKey
		                        if ( ( sub_args['nohashcheck'] === false ) && ! sign_addr.matchPubKey ) { //exit with an error if the address does not contain the pubKey hash
		                                throw {'msg': `The ${sign_addr.type} address '${sign_addr.addr}' in the COSE_Sign1 does not belong to the public key in the COSE_Key.`};
					}
				}

			// 2) unprotectedHeader -> get the value for the isHashed boolean

				var unprotectedHeader = COSE_Sign1_structure[1];
				// cbor decode generates an object out of a map if there is only one entry. we want always a map, because there could be more entries
				if ( unprotectedHeader instanceof Map == false && typeof unprotectedHeader === 'object' ) { // so if it is not a map but an object, convert it
					var unprotectedHeader = new Map(Object.entries(unprotectedHeader));
				}

				if ( unprotectedHeader instanceof Map == false ) { // if its not a map now, throw an error
					throw {'msg': `Unprotected header is not a map`};
				}

				if ( ! unprotectedHeader.has('hashed') ) { throw {'msg': `Unprotected header label 'hashed' is missing`}; }
				var isHashed = unprotectedHeader.get('hashed');
				if ( typeof isHashed !== 'boolean' ) { throw {'msg': `Unprotected header label 'hashed' is not a boolean`}; }

				//if there is already a payload_data_hex present via the optional data parameters, hash it if needed to match the settings in the COSE_Sign1 signature
				if ( payload_data_hex && isHashed ) { payload_data_hex = getHash(payload_data_hex, 28); } //hash the payload with blake2b_224 (28bytes digest length) }

			// 3) payload

				//if there is no payload_data_hex present via the optional data parameters, use the one in the COSE_Sign1 signature
				if ( typeof payload_data_hex === 'undefined' ) {
					var payload_data_buffer = COSE_Sign1_structure[2];
					if ( Buffer.isBuffer(payload_data_buffer) ) { // payload present, load it into payload_data_hex
						var payload_data_hex = payload_data_buffer.toString('hex');
					} else if ( payload_data_buffer == null ) { // payload is missing, and there is also no payload provided via the optional data parameters
						throw {'msg': `There is no payload present in the COSE_Sign1 signature, please provide a payload via the data / data-hex / data-file parameters`};
					}
				}

			// 4) signature

				var signature_buffer = COSE_Sign1_structure[3];
				if ( ! Buffer.isBuffer(signature_buffer) ) { throw {'msg': `Signature is not a bytearray`}; }
				var signature_hex = signature_buffer.toString('hex')

				//load the Ed25519Signature
				try {
				var ed25519signature = CardanoWasm.Ed25519Signature.from_hex(signature_hex);
				} catch (error) { throw {'msg': `${error}`}; }

			//generate the protectedHeader with the current values (the address within it might have been overwritten by a given one)
			// alg (1) - must be set to EdDSA (-8)
			// kid (4) - Optional, if present must be set to the same value as in the COSE_Key specified below. It is recommended to be set to the same value as in the "address" header.
			// "address" - must be set to the raw binary bytes of the address as per the binary spec, without the CBOR binary wrapper tag
//			var protectedHeader_cbor_hex = Buffer.from(cbor.encode(new Map().set(1,-8).set('address',Buffer.from(sign_addr.hex,'hex')))).toString('hex')
//			var protectedHeader_cbor_hex = Buffer.from(cbor.encode(new Map().set(1,-8).set(4,Buffer.from(sign_addr.hex,'hex')).set('address',Buffer.from(sign_addr.hex,'hex')))).toString('hex')
			var protectedHeader_cbor_hex = cbor.encode(protectedHeader).toString('hex')

			//generate the data to verify, as a serialized cbor of the Sig_structure
			//Sig_structure = [
			//  context : "Signature" / "Signature1" / "CounterSignature",    ; Signature1 (Sign1) here
			//  body_protected : empty_or_serialized_map,                     ; protected from layer 1
			//  ? sign_protected : empty_or_serialized_map,                   ; not present in Sign1 case
			//  external_aad : bstr,                                          ; empty here
			//  payload : bstr
			//  ]
			var Sig_structure = [ "Signature1", Buffer.from(protectedHeader_cbor_hex,'hex'),Buffer.from(''), Buffer.from(payload_data_hex,'hex') ]

			//convert it to cbor representation
			Sig_structure_cbor_hex = cbor.encode(Sig_structure).toString('hex');

			//VERIFY
			var verified = publicKey.verify(Buffer.from(Sig_structure_cbor_hex,'hex'),ed25519signature);

			//compose the content for the output
			if ( sub_args['json'] === true ) { //generate content in json format
				var content = `{ "result": "${verified}" }`;
			} else if ( sub_args['json-extended'] === true ) { //generate content in json format with additional fields
				var content = `{ "workMode": "${workMode}", "result": "${verified}", "addressHex": "${sign_addr.hex}", "addressType": "${sign_addr.type}", "addressNetwork": "${sign_addr.network}", `;
				if ( payload_data_hex.length <= 2000000 ) { content += `"payloadDataHex": "${payload_data_hex}", `; } //only include the payload_data_hex if it is less than 2M of chars
				content += `"isHashed": "${isHashed}",`;
				if ( Sig_structure_cbor_hex.length <= 2000000 ) { content += `"verifyDataHex": "${Sig_structure_cbor_hex}", `; } //only include the Sig_structure_cbor_hex if it is less than 2M of chars
				content += `"signature": "${signature_hex}", "publicKey": "${pubKey}"`;
				if ( sub_args['include-maps'] === true ) { //generate content also with JSON-Maps for the COSE_Key, COSE_Sign1 and verifyData structures
					content += `, "maps": { "COSE_Key": ${mapToJs(COSE_Key_structure)}, "COSE_Sign1": ${mapToJs(COSE_Sign1_structure)}, "verifyData": ${mapToJs(Sig_structure)}, "protectedHeader": ${mapToJs(protectedHeader)} }` }
				content += ` }`
			} else { //generate content in text format
				var content = `${verified}`;
			}

			//return the content & the verified boolean
			return {
				'content': content,
				'verified': verified,
			}

}


// SIGN CIP8/30 FUNCTION -> coded as a function so it can be reused within other functions
function signCIP8(workMode = "sign-cip8", calling_args = process.argv.slice(3)) { //default calling arguments are the same as calling the main process - can be modified by subfunctions

			var sub_args = require('minimist')(calling_args,parse_options);

			//get signing key -> store it in sign_key
			var key_file_hex = sub_args['secret-key'];
		        if ( typeof key_file_hex === 'undefined' || key_file_hex === true ) { throw {'msg': `Missing secret key parameter`, 'showUsage': workMode}; }

			//read in the key from a file or direct hex
		        sign_key = readKey2hex(key_file_hex, 'secret');

			//load the private key (normal or extended)
			try {
			if ( sign_key.length <= 64 ) { var prvKey = CardanoWasm.PrivateKey.from_normal_bytes(Buffer.from(sign_key, "hex")); }
						else { var prvKey = CardanoWasm.PrivateKey.from_extended_bytes(Buffer.from(sign_key.substring(0,128), "hex")); } //use only the first 64 bytes (128 chars)
			} catch (error) { throw {'msg': `${error}`}; }

			//generate the public key from the secret key for external verification
			var pubKey = Buffer.from(prvKey.to_public().as_bytes()).toString('hex')

			//get signing address (stake or paymentaddress in bech format)
			var address = sub_args['address'];
		        if ( typeof address === 'undefined' || address === true ) { throw {'msg': `Missing signing address parameter`, 'showUsage': workMode}; }

			//read the address from a file or direct hex/bech. also do a match check against the public key
		        sign_addr = readAddr2hex(address, pubKey);

			//check that the given address belongs to the current network
			if ( ( sign_addr.network == 'mainnet' ) && !(typeof sub_args['testnet-magic'] === 'undefined') ) { // check for mainnet address
				throw {'msg': `The mainnet ${sign_addr.type} address '${sign_addr.addr}' does not match your current '--testnet-magic xxx' setting.`}; }
			else if ( ( sign_addr.network == 'testnet' ) && (typeof sub_args['testnet-magic'] === 'undefined') ) { // check for testnet address
				throw {'msg': `The testnet ${sign_addr.type} address '${sign_addr.addr}' does not match your current setting. Use '--testnet-magic xxx' for testnets.`}; }

                        //check that the given address belongs to the pubKey
                        if ( sub_args['nohashcheck'] === false && ! sign_addr.matchPubKey ) { //exit with an error if the address does not contain the pubKey hash
                                throw {'msg': `The ${sign_addr.type} address '${sign_addr.addr}' does not belong to the provided secret key.`}; process.exit(1);
			}

			//get payload-hex to sign -> store it in payload_data_hex
			var payload_data_hex = sub_args['data-hex'];
		        if ( typeof payload_data_hex === 'undefined' || payload_data_hex === true ) {

				//no data-hex parameter present, lets try the data parameter
				var payload_data = sub_args['data'];
			        if ( typeof payload_data === 'undefined' || payload_data === true ) {

					//no data parameter present, lets try the data-file parameter
					var payload_data_file = sub_args['data-file'];
				        if ( typeof payload_data_file === 'undefined' || payload_data_file === true ) {throw {'msg': `Missing data / data-hex / data-file to sign`, 'showUsage': workMode}; }

					//data-file present lets read the file and store it hex encoded in payload_data_hex
					try {
						payload_data_hex = fs.readFileSync(payload_data_file,null).toString('hex'); //reads the file as binary
					} catch (error) { throw {'msg': `Can't read data-file '${payload_data_file}'`}; }

				} else {
				//data parameter present, lets convert it to hex and store it in the payload_data_hex variable
				payload_data_hex = Buffer.from(payload_data).toString('hex');
				}

			} else {
				//data-hex is present, lets trim it, convert it to lowercase
			        payload_data_hex = trimString(payload_data_hex.toLowerCase());
				//check that the given data is a hex string, skip the test if payload_data_hex is empty. a nullstring is ok.
				if ( payload_data_hex != '' && ! regExpHex.test(payload_data_hex) ) { throw {'msg': `Data to sign is not a valid hex string`}; }
			}

			var payload_data_hex_orig = payload_data_hex //copy the payload_data_hex for later json output (in case its hashed)

			//generate the protectedHeader as an inner cbor (serialized Map)
			// alg (1) - must be set to EdDSA (-8)
			// kid (4) - Optional, if present must be set to the same value as in the COSE_Key specified below. It is recommended to be set to the same value as in the "address" header.
			// "address" - must be set to the raw binary bytes of the address as per the binary spec, without the CBOR binary wrapper tag
			var protectedHeader_cbor_hex = Buffer.from(cbor.encode(new Map().set(1,-8).set('address',Buffer.from(sign_addr.hex,'hex')))).toString('hex')

			//hash the payload if its set via the flag --hashed. this is used if the payload gets too big, or if f.e. a hw-wallet cannot display the payload (non ascii)
			var isHashed = sub_args['hashed'];
			if ( isHashed ) { payload_data_hex = getHash(payload_data_hex, 28); } //hash the payload with blake2b_224 (28bytes digest length) }

			//generate the unprotectedHeader map
			var unprotectedHeader = new Map().set('hashed', isHashed) // { "hashed": true/false }

			//generate the data to sign, as a serialized cbor of the Sig_structure
			//Sig_structure = [
			//  context : "Signature" / "Signature1" / "CounterSignature",    ; Signature1 (Sign1) here
			//  body_protected : empty_or_serialized_map,                     ; protected from layer 1
			//  ? sign_protected : empty_or_serialized_map,                   ; not present in Sign1 case
			//  external_aad : bstr,                                          ; empty here
			//  payload : bstr
			//  ]
			var Sig_structure = [ "Signature1", Buffer.from(protectedHeader_cbor_hex,'hex'),Buffer.from(''), Buffer.from(payload_data_hex,'hex') ]

			//convert it to cbor representation
			Sig_structure_cbor_hex = cbor.encode(Sig_structure).toString('hex');

			//sign the data
			try {
			var signedBytes = prvKey.sign(Buffer.from(Sig_structure_cbor_hex, 'hex')).to_bytes();
			var signature_hex = Buffer.from(signedBytes).toString('hex');
			} catch (error) { throw {'msg': `${error}`}; }

			//generate the signed message structure
			//COSE_Sign1_structure = [
			//  bstr,               ; protected header
			//  { * label => any }, ; unprotected header
			//  bstr / nil,         ; message(payload) to sign
			//  bstr                ; signature
			//  ]
			if ( sub_args['nopayload'] ) { //the payload can be excluded from the COSE_Sign1 signature if the payload is known by the involved entities
				var COSE_Sign1_structure = [ Buffer.from(protectedHeader_cbor_hex,'hex'), unprotectedHeader, null , Buffer.from(signature_hex,'hex') ]
			} else {
				var COSE_Sign1_structure = [ Buffer.from(protectedHeader_cbor_hex,'hex'), unprotectedHeader, Buffer.from(payload_data_hex,'hex'), Buffer.from(signature_hex,'hex') ]
			}

			//convert it to cbor representation
			var COSE_Sign1_cbor_hex = cbor.encode(COSE_Sign1_structure).toString('hex');

			//generate the COSE_Key structure with the following headers set:
			//kty (1) - must be set to OKP (1)
			//kid (2) - Optional, if present must be set to the same value as in the Sig_structures protectedHeader_cbor via map entry (4)
			//alg (3) - must be set to EdDSA (-8)
			//crv (-1) - must be set to Ed25519 (6)
			//x (-2) - must be set to the public key bytes of the key used to sign the Sig_structure
			var COSE_Key_structure = new Map().set(1,1).set(3,-8).set(-1,6).set(-2, Buffer.from(pubKey,'hex'));

			//convert it to cbor representation
			var COSE_Key_cbor_hex = cbor.encode(COSE_Key_structure).toString('hex');

			//compose the content for the output: signature data + key
			if ( sub_args['json'] === true ) { //generate content in json format
				var content = `{ "COSE_Sign1_hex": "${COSE_Sign1_cbor_hex}", "COSE_Key_hex": "${COSE_Key_cbor_hex}" }`;
			} else if ( sub_args['json-extended'] === true ) { //generate content in json format with additional fields

				//generate the format displayed to the user 'Cardano Message' prefix='cms_' + COSE_Sign1(base64url encoded) + fnv32a_hash as checksum(bash64url encoded)
				const signedMsg_prefix = 'cms_';
				const signedMsg_data = base64url.encode(Buffer.from(COSE_Sign1_cbor_hex,'hex'));
				const signedMsg_checksum = base64url.encode(Buffer.from(new Uint8Array(new Uint32Array([ fnv32.fnv_1a(Buffer.from(COSE_Sign1_cbor_hex,'hex')) ]).buffer).reverse()));
				const signedMsg = signedMsg_prefix + signedMsg_data + signedMsg_checksum

				var prvKeyHex = Buffer.from(prvKey.as_bytes()).toString('hex');
				var content = `{ "workMode": "${workMode}", "addressHex": "${sign_addr.hex}", "addressType": "${sign_addr.type}", "addressNetwork": "${sign_addr.network}", `;
				if ( payload_data_hex_orig.length <= 2000000 ) { content += `"inputDataHex": "${payload_data_hex_orig}", `; } //only include the payload_data_hex if it is less than 2M of chars
				content += `"isHashed": "${isHashed}",`;
				if ( isHashed ) { content += `"hashedInputDataHex": "${payload_data_hex}", `; } //only include the payload_data_hex(now in hashed format) if isHashed is true
				if ( Sig_structure_cbor_hex.length <= 2000000 ) { content += `"signDataHex": "${Sig_structure_cbor_hex}", `; } //only include the Sig_structure_cbor_hex if it is less than 2M of chars
				content += `"signature": "${signature_hex}",`;
				content += `"secretKey": "${prvKeyHex}", "publicKey": "${pubKey}", `
				content += `"output": { "signedMessage": "${signedMsg}", "COSE_Sign1_hex": "${COSE_Sign1_cbor_hex}", "COSE_Key_hex": "${COSE_Key_cbor_hex}" } }`;

			} else { //generate content in text format
				var content = COSE_Sign1_cbor_hex + " " + COSE_Key_cbor_hex;
			}

			//return the whole content and also the COSE_Sign1 & COSE_Key
			return {
				'content': content,
				'cose_sign1_cbor_hex': COSE_Sign1_cbor_hex,
				'cose_key_cbor_hex': COSE_Key_cbor_hex
			}


}






// MAIN
//
//

async function main() {

        //show help or usage if no parameter is provided
        if ( ! process.argv[2] || process.argv[2].toLowerCase().includes('help') || process.argv[2].toLowerCase().includes('usage') ) { console.log(`${appname} ${version}`); showUsage(); }

        //show version
        if ( process.argv[2].toLowerCase().includes('version') ) { console.log(`${appname} ${version}`); process.exit(0); }

        //first parameter - workMode: "sign or verify"
        var workMode = process.argv[2];
        if ( ! workMode ) { showUsage(); }
        workMode = trimString(workMode.toLowerCase());

	//CIP8-Flag-Check
        if ( args['cip8'] === true ) {workMode = workMode + '-cip8'}

	//CIP30-Flag-Check
        if ( args['cip30'] === true ) {workMode = workMode + '-cip30'}

	//CIP36-Flag-Check
        if ( args['cip36'] === true ) {
		workMode = workMode + '-cip36'
		//add deregister in CIP36 mode if the flag was set
		if ( args['deregister'] === true ) { workMode = workMode + "-deregister" }
	}

	//CIP88-Flag-Check
        if ( args['cip88'] === true ) {workMode = workMode + '-cip88'}

	//CIP100-Flag-Check
        if ( args['cip100'] === true ) {workMode = workMode + '-cip100'}

	//LEDGER-Flag-Check
        if ( args['ledger'] === true ) {workMode = workMode + '-ledger'}

	//TREZOR-Flag-Check
        if ( args['trezor'] === true ) {workMode = workMode + '-trezor'}

	//show usage for the workMode
	if ( args['help'] === true ) { showUsage(workMode); }

	//choose the workMode
        switch (workMode) {


                case "sign":  //SIGN DATA IN DEFAULT MODE

			//get data-hex to sign -> store it in sign_data_hex
			var sign_data_hex = args['data-hex'];
		        if ( typeof sign_data_hex === 'undefined' || sign_data_hex === true ) {

				//no data-hex parameter present, lets try the data parameter
				var sign_data = args['data'];
			        if ( typeof sign_data === 'undefined' || sign_data === true ) {

					//no data parameter present, lets try the data-file parameter
					var sign_data_file = args['data-file'];
				        if ( typeof sign_data_file === 'undefined' || sign_data_file === true ) {console.error(`Error: Missing data / data-hex / data-file to sign`); showUsage(workMode);}

					//data-file present lets read the file and store it hex encoded in sign_data_hex
					try {
						sign_data_hex = fs.readFileSync(sign_data_file,null).toString('hex'); //reads the file as binary
					} catch (error) { console.error(`Error: Can't read data-file '${sign_data_file}'`); process.exit(1); }

				} else {
				//data parameter present, lets convert it to hex and store it in the sign_data_hex variable
				sign_data_hex = Buffer.from(sign_data).toString('hex');
				}

			}
		        sign_data_hex = trimString(sign_data_hex.toLowerCase());

			//check that the given data is a hex string, skip the test for an empty string. a nullstring is ok
			if ( sign_data_hex != '' && ! regExpHex.test(sign_data_hex) ) { console.error(`Error: Data to sign is not a valid hex string`); process.exit(1); }

			//get signing key -> store it in sign_key
			var key_file_hex = args['secret-key'];
		        if ( typeof key_file_hex === 'undefined' || key_file_hex === true ) { console.error(`Error: Missing secret key parameter`); showUsage(workMode); }

			//read in the key from a file or direct hex
		        sign_key = readKey2hex(key_file_hex, 'secret');

			//load the private key (normal or extended)
			try {
			if ( sign_key.length <= 64 ) { var prvKey = CardanoWasm.PrivateKey.from_normal_bytes(Buffer.from(sign_key, "hex")); }
						else { var prvKey = CardanoWasm.PrivateKey.from_extended_bytes(Buffer.from(sign_key.substring(0,128), "hex")); } //use only the first 64 bytes (128 chars), rest is publicKey + chainCode
			} catch (error) { console.error(`Error: ${error}`); process.exit(1); }

			//generate the public key from the secret key for external verification
			var pubKey = Buffer.from(prvKey.to_public().as_bytes()).toString('hex')

			//check the pubKey against an optionally provided bech32 address via the --address parameter
                        var address = args['address'];
                        if ( typeof address === 'string' ) { //do the check if the parameter is provided

				//read the address from a file or direct hex/bech. also do a match check against the public key
			        var sign_addr = readAddr2hex(address, pubKey);

	                        if ( ! sign_addr.matchPubKey ) { //exit with an error if the address does not contain the pubKey hash
					console.error(`Error: The ${sign_addr.type} address '${sign_addr.addr}' does not belong to the provided secret key.`); process.exit(1);
				}
			}

			//sign the data
			try {
			var signedBytes = prvKey.sign(Buffer.from(sign_data_hex, 'hex')).to_bytes();
			var signature = Buffer.from(signedBytes).toString('hex');
			} catch (error) { console.error(`Error: ${error}`); process.exit(1); }

			//if jcli-flag is set, convert the signature and publickey into the jcli bech-format
			//with prefix ed25519_sig and ed25519_pk
			if ( args['jcli'] === true ) { //convert signature and publickey in bech format
				try {
				signature = bech32.encode("ed25519_sig", bech32.toWords(Buffer.from(signature, "hex")), 128); //encode in bech32 with a raised limit to 128 words (signature is longer than the default limit of 90 words)
				pubKey = bech32.encode("ed25519_pk", bech32.toWords(Buffer.from(pubKey, "hex"))); //encode in bech32
				} catch (error) { console.error(`${error}\nCouldn't encode signature/pubKey into bech string.`); process.exit(1); }
			}

			//compose the content for the output: signature data + public key
			if ( args['json'] === true ) { //generate content in json format
				var content = `{ "signature": "${signature}", "publicKey": "${pubKey}" }`;
			} else if ( args['json-extended'] === true ) { //generate content in json format with additional fields
				var prvKeyHex = Buffer.from(prvKey.as_bytes()).toString('hex');
				var content = `{ "workMode": "${workMode}", `;
				if ( sign_data_hex.length <= 2000000 ) { content += `"signDataHex": "${sign_data_hex}", `; } //only include the sign_data_hex if it is less than 2M of chars
				if ( sign_addr ) { content += `"addressHex": "${sign_addr.hex}", "addressType": "${sign_addr.type}", "addressNetwork": "${sign_addr.network}", `; } //only include the signing address if provided
				content += `"signature": "${signature}", "secretKey": "${prvKeyHex}", "publicKey": "${pubKey}" }`;
			} else { //generate content in text format
				var content = signature + " " + pubKey;
			}

			//output the signature data and the public key to the console or to a file
			var out_file = args['out-file'];
		        //if there is no --out-file parameter specified or the parameter alone (true) then output to the console
			if ( typeof out_file === 'undefined' || out_file === true ) { console.log(content);} //Output to console
			else { //else try to write the content out to the given file
				try {
				fs.writeFileSync(out_file,content, 'utf8')
				// file written successfully
				} catch (error) { console.error(`${error}`); process.exit(1); }
			}
			break;



                case "sign-cip8":  //SIGN DATA IN CIP-8 MODE -> currently idential to CIP-30
                case "sign-cip30":  //SIGN DATA IN CIP-30 MODE -> CIP-8 structure

			//call signing subfunction
			try {
				var result = signCIP8(workMode);  //no extra arguments than `workMode` means that the function takes the parameters from the main process call
			} catch (error) {
				console.error(`Error: ${error.msg}`);
				if ( error.showUsage ) { showUsage(workMode); }
				process.exit(1);
			}

			//output the signature data and the public key to the console or to a file
			var out_file = args['out-file'];
		        //if there is no --out-file parameter specified or the parameter alone (true) then output to the console
			if ( typeof out_file === 'undefined' || out_file === true ) { console.log(result.content); }
			else { //else try to write the content out to the given file
				try {
				fs.writeFileSync(out_file,result.content, 'utf8')
				// file written successfully
				} catch (error) { console.error(`${error}`); process.exit(1); }
			}
			break;



                case "sign-cip36":  //SIGN REGISTRATION DATA IN CIP-36 MODE (Catalyst)

			//get rewards payoutaddress in bech format (must be a payment address again starting with catalyst fund10)
			var address = args['payment-address'];
		        if ( typeof address === 'undefined' || address === true ) { console.error(`Error: Missing rewards payout address (--payment-address)`); showUsage(workMode); }

			//read the address from a file or direct hex/bech
		        rewards_addr = readAddr2hex(address);

			//check that the rewards address is a payment address
			if ( ! rewards_addr.type.includes('payment') ) { console.error(`Error: The rewards address '${rewards_addr.addr}' is not a payment address starting with 'addr...'`); process.exit(1); }

			//check that the given address belongs to the current network
			if ( ( rewards_addr.network == 'mainnet' ) && !(typeof args['testnet-magic'] === 'undefined') ) { // check for mainnet address
				console.error(`Error: The mainnet ${rewards_addr.type} address '${rewards_addr.addr}' does not match your current '--testnet-magic xxx' setting.`); process.exit(1); }
			else if ( ( rewards_addr.network == 'testnet' ) && (typeof args['testnet-magic'] === 'undefined') ) { // check for testnet address
				console.error(`Error: The testnet ${rewards_addr.type} address '${rewards_addr.addr}' does not match your current setting. Use '--testnet-magic xxx' for testnets.`); process.exit(1); }

			//get signing key -> store it in sign_key
			var key_file_hex = args['secret-key'];
		        if ( typeof key_file_hex === 'undefined' || key_file_hex === true ) { console.error(`Error: Missing secret key parameter`); showUsage(workMode); }

			//read in the key from a file or direct hex
		        sign_key = readKey2hex(key_file_hex, 'secret');

			//load the private key (normal or extended)
			try {
			if ( sign_key.length <= 64 ) { var prvKey = CardanoWasm.PrivateKey.from_normal_bytes(Buffer.from(sign_key, "hex")); }
						else { var prvKey = CardanoWasm.PrivateKey.from_extended_bytes(Buffer.from(sign_key.substring(0,128), "hex")); } //use only the first 64 bytes (128 chars)
			} catch (error) { console.error(`Error: ${error}`); process.exit(1); }

			//generate the public key from the secret signing stake key
			var pubKey = Buffer.from(prvKey.to_public().as_bytes()).toString('hex')

			//do a registration with provided vote_public_keys
			//--deregister must be specified as an extra flag to avoid deregistrations by accident
			var vote_delegation_array = [];
			var all_vote_keys_array = [];  //used to check for duplicates later
			var all_weights_array = [];  //used for an extended json output later
			var total_vote_weight = 0;	//used to calculate the total-vote-weight. this must be higher than zero. otherwise all vote-weights are zero -> edge case

			//get deleg vote public key(s) -> store it in vote_public_key
			var vote_public_key = args['vote-public-key'];
		        if ( typeof vote_public_key === 'undefined' ) { console.error(`Error: Missing vote public key(s) parameter. For a deregistration please use the flag --deregister.`); showUsage(workMode); }

			//if there is only one --vote-public-key parameter present, convert it to an array
		        if ( typeof vote_public_key === 'string' ) { vote_public_key = [ vote_public_key ]; }

			//get deleg voting weight -> store it in vote_weight
			var vote_weight = args['vote-weight'];
		        if ( typeof vote_weight === 'undefined' ) { vote_weight = 1 }
			if ( vote_weight === true ) { console.error(`Error: Please specify a --vote-weight parameter with an unsigned integer value >= 0`); process.exit(1); }

			//if there is only one --vote-weight parameter present, convert it to an array
		        if ( typeof vote_weight === 'number' ) { vote_weight = [ vote_weight ]; }

			//if not the same amounts of vote_public_keys and vote_weights provided, show an error
			if ( vote_public_key.length != vote_weight.length ) { console.error(`Error: Not the same count of --vote-public-key(` + vote_public_key.length + `) and --vote-weight(` + vote_weight.length + `) parameters`); process.exit(1); }

			//build the vote_delegation array
			for (let cnt = 0; cnt < vote_public_key.length; cnt++) {
				entry_vote_public_key = vote_public_key[cnt]
			        if ( typeof entry_vote_public_key === 'number' || entry_vote_public_key === true ) { console.error(`Error: Invalid --vote-public-key parameter found, please use a filename, hex- or bech-string`); process.exit(1); }
				entry_vote_public_key_hex = readKey2hex(entry_vote_public_key, 'public');
				entry_vote_weight = vote_weight[cnt];
				if (typeof entry_vote_weight !== 'number' || entry_vote_weight < 0) { console.error(`Error: Please specify a --vote-weight parameter with an unsigned integer value >= 0`); process.exit(1); }
				vote_delegation_array.push([Buffer.from(entry_vote_public_key_hex,'hex'),entry_vote_weight]) //add the entry to the delegation array
				all_vote_keys_array.push(entry_vote_public_key_hex) //collect all hex public keys in an extra array to quickly find duplicates/public-signing-key-compare afterwards
				all_weights_array.push(entry_vote_weight) //collect all voting weights in an extra array for an extended json output later
				total_vote_weight += entry_vote_weight //sums up all the weights to do a check against zero at the end
			}

			/* removed duplicates check with v1.7.1
			//check for duplicated key entries
			hasDuplicates = all_vote_keys_array.some((element, index) => { return all_vote_keys_array.indexOf(element) !== index });
			if (hasDuplicates) { console.error(`Error: Duplicated resolved vote-public-key entries found. Please only use a vote-public-key one time in a delegation.`); process.exit(1); }
			*/

			//check that no vote-public-key is identical with the public-key of the signing secret key. vote-public-key is derived from a different path, so a match would be a wrong vote-public-key
			if (all_vote_keys_array.indexOf(pubKey) > -1) { console.error(`Error: Wrong vote-public-key entry found, or your secret-key is a wrong one. The vote-public-key(s) must be different from the public-key of the signing stake-secret-key.`); process.exit(1); }

			//check that the total_vote_weight is not zero
			if (total_vote_weight == 0) { console.error(`Error: Total vote-weight is zero, please make sure that at least one vote-public-key has a vote-weight > 0`); process.exit(1); }

			//get the --nonce parameter
			var nonce = args['nonce'];
		        if ( typeof nonce === 'undefined' ) { var totalUtcSeconds = Math.floor(new Date().getTime() / 1000); nonce = 4492800 + (totalUtcSeconds - 1596059091) }  //if not defined, set it to the slotHeight of cardano-mainnet
		        else if ( typeof nonce !== 'number' || nonce === true || nonce < 0 ) { console.error(`Error: Please specify a --nonce parameter with an unsigned integer value > 0, or remove the parameter so the mainnet slotHeight will be calculated from current time`); process.exit(1); }

			//get the --vote-purpose parameter, set default = 0
			var vote_purpose_param = args['vote-purpose'];

		        if ( typeof vote_purpose_param === 'undefined' ) { vote_purpose = 0 }  //if not defined, set it to default=0
		        else if ( typeof vote_purpose_param === 'number' && vote_purpose_param >= 0 ) { vote_purpose = vote_purpose_param }
			else { console.error(`Error: Please specify a --vote-purpose parameter with an unsigned integer value >= 0`); process.exit(1); }

			//get a cleartext description of the purpose (shown in the --json-extended output
			switch (vote_purpose) {
				case 0: var vote_purpose_description="Catalyst"; break;
				default: var vote_purpose_description="Unknown";
			}

			/*
			build the delegation map
			61284: {
				  1: [[<vote_public_key_1>, <vote_weight_1>], [<vote_public_key_2>, <vote_weight_2>]],	// delegations - byte array(s) of the voting_public_keys and the relative voting_weight(unsigned int)
				  2: <stake_public_key>, // stake_pub - byte array
				  3: <payment_rewards_address>, // reward_address - byte array
				  4: <nonce> // nonce = slotHeight (tip)
				  5: <voting_purpose> // voting_purpose: 0 = Catalyst
			}
			*/
			const delegationMap = new Map().set(61284,new Map().set(1,vote_delegation_array).set(2,Buffer.from(pubKey,'hex')).set(3,Buffer.from(rewards_addr.hex,'hex')).set(4,nonce).set(5,vote_purpose));

			//convert it to a cbor hex string
			const delegationCBOR = Buffer.from(cbor.encode(delegationMap)).toString('hex');

			//hash the delegationCBOR hex string
			var sign_data_hex = getHash(delegationCBOR);

			//sign the data
			try {
			var signedBytes = prvKey.sign(Buffer.from(sign_data_hex, 'hex')).to_bytes();
			var signature = Buffer.from(signedBytes).toString('hex');
			} catch (error) { console.error(`Error: ${error}`); process.exit(1); }

			/*
			build the full registration map by adding the root key 61285 and the signature in key 1 below that like
			61285 : {
				   1: <signature>  // signed signature(byte array) from the stake_secret_key
			}
			*/
			var registrationMap = delegationMap.set(61285,new Map().set(1,Buffer.from(signature,'hex')))

			//convert it to a cbor hex string
			var registrationCBOR = Buffer.from(cbor.encode(registrationMap)).toString('hex');

			//compose the content for the output as JSON registration, extended JSON data or plain registrationCBOR
			if ( args['json'] === true ) { //generate content in json format
				var delegations = [];
				for (let cnt = 0; cnt < all_vote_keys_array.length; cnt++) {
				delegations.push(`[ "0x${all_vote_keys_array[cnt]}", ${all_weights_array[cnt]} ]`)
				}
				var content = `{ "61284": { "1": [ ${delegations} ], "2": "0x${pubKey}", "3": "0x${rewards_addr.hex}", "4": ${nonce}, "5": ${vote_purpose} }, "61285": { "1": "0x${signature}" } }`;
			} else if ( args['json-extended'] === true ) { //generate content in json format with additional fields
				var prvKeyHex = Buffer.from(prvKey.as_bytes()).toString('hex');
				var content = `{ "workMode": "${workMode}", "votePurpose": "${vote_purpose_description} (${vote_purpose})", "totalVoteWeight": ${total_vote_weight}, "paymentAddressHex": "${rewards_addr.hex}", "paymentAddressType": "${rewards_addr.type}", "paymentAddressNetwork": "${rewards_addr.network}", "signDataHex": "${sign_data_hex}", "signature": "${signature}", "secretKey": "${prvKeyHex}", "publicKey": "${pubKey}", `;
				var delegations = [];
				for (let cnt = 0; cnt < all_vote_keys_array.length; cnt++) {
				delegations.push(`[ "0x${all_vote_keys_array[cnt]}", ${all_weights_array[cnt]} ]`)
				}
				content += `"output": { "cbor": "${registrationCBOR}", "json": { "61284": { "1": [ ${delegations} ], "2": "0x${pubKey}", "3": "0x${rewards_addr.hex}", "4": ${nonce}, "5": ${vote_purpose} }, "61285": { "1": "0x${signature}" } } } }`;
			} else { //generate content in text format
				var content = `${registrationCBOR}`;
			}

			//output the content to the console or to a file
			var out_file = args['out-file'];
		        //if there is no --out-file parameter specified or the parameter alone (true) then output to the console
			if ( typeof out_file === 'undefined' || out_file === true ) { console.log(content); }
			else { //else try to write the content out to the given file
				try {
				fs.writeFileSync(out_file,content, 'utf8')
				// file written successfully
				} catch (error) { console.error(`${error}`); process.exit(1); }
			}

			//output the registrationCBOR to a binary file
			var out_cbor = args['out-cbor'];
		        //if there is a --out-cbor parameter specified then try to write output as a binary cbor file
			if ( typeof out_cbor === 'string' ) {
				try {
				var writeBuf = Buffer.from(registrationCBOR,'hex')
				fs.writeFileSync(out_cbor, writeBuf, 'binary')
				} catch (error) { console.error(`${error}`); process.exit(1); }
			}
			break;



                case "sign-cip36-deregister":  //SIGN DEREGISTRATION DATA IN CIP-36 MODE (Catalyst)

			//get signing key -> store it in sign_key
			var key_file_hex = args['secret-key'];
		        if ( typeof key_file_hex === 'undefined' || key_file_hex === true ) { console.error(`Error: Missing secret key parameter`); showUsage(workMode); }

			//read in the key from a file or direct hex
		        sign_key = readKey2hex(key_file_hex, 'secret');

			//load the private key (normal or extended)
			try {
			if ( sign_key.length <= 64 ) { var prvKey = CardanoWasm.PrivateKey.from_normal_bytes(Buffer.from(sign_key, "hex")); }
						else { var prvKey = CardanoWasm.PrivateKey.from_extended_bytes(Buffer.from(sign_key.substring(0,128), "hex")); } //use only the first 64 bytes (128 chars)
			} catch (error) { console.error(`Error: ${error}`); process.exit(1); }

			//generate the public key from the secret signing stake key
			var pubKey = Buffer.from(prvKey.to_public().as_bytes()).toString('hex')

			//get the --nonce parameter
			var nonce = args['nonce'];
		        if ( typeof nonce === 'undefined' ) { var totalUtcSeconds = Math.floor(new Date().getTime() / 1000); nonce = 4492800 + (totalUtcSeconds - 1596059091) }  //if not defined, set it to the slotHeight of cardano-mainnet
		        else if ( typeof nonce !== 'number' || nonce === true || nonce < 0 ) { console.error(`Error: Please specify a --nonce parameter with an unsigned integer value > 0, or remove the parameter so the mainnet slotHeight will be calculated from current time`); process.exit(1); }

			//get the --vote-purpose parameter, set default = 0
			var vote_purpose_param = args['vote-purpose'];

		        if ( typeof vote_purpose_param === 'undefined' ) { vote_purpose = 0 }  //if not defined, set it to default=0
		        else if ( typeof vote_purpose_param === 'number' && vote_purpose_param >= 0 ) { vote_purpose = vote_purpose_param }
			else { console.error(`Error: Please specify a --vote-purpose parameter with an unsigned integer value >= 0`); process.exit(1); }

			//get a cleartext description of the purpose (shown in the --json-extended output
			switch (vote_purpose) {
				case 0: var vote_purpose_description="Catalyst"; break;
				default: var vote_purpose_description="Unknown";
			}

			/*
			build the deregistration map
			61286: {
				  1: <stake_public_key>, // stake_pub - byte array
				  2: <nonce> // nonce = slotHeight (tip)
				  3: <voting_purpose> // voting_purpose: 0 = Catalyst
			}
			*/
			const dereg_Map = new Map().set(61286,new Map().set(1,Buffer.from(pubKey,'hex')).set(2,nonce).set(3,vote_purpose));

			//convert it to a cbor hex string
			const dereg_CBOR = Buffer.from(cbor.encode(dereg_Map)).toString('hex');

			//hash the deregistrationCBOR hex string
			var sign_data_hex = getHash(dereg_CBOR);

			//sign the data
			try {
			var signedBytes = prvKey.sign(Buffer.from(sign_data_hex, 'hex')).to_bytes();
			var signature = Buffer.from(signedBytes).toString('hex');
			} catch (error) { console.error(`Error: ${error}`); process.exit(1); }

			/*
			build the full deregistration map by adding the root key 61285 and the signature in key 1 below that like
			61285 : {
				   1: <signature>  // signed signature(byte array) from the stake_secret_key
			}
			*/
			const deregistrationMap = dereg_Map.set(61285,new Map().set(1,Buffer.from(signature,'hex')))

			//convert it to a cbor hex string
			const deregistrationCBOR = Buffer.from(cbor.encode(deregistrationMap)).toString('hex');

			//compose the content for the output as JSON registration, extended JSON data or plain registrationCBOR
			if ( args['json'] === true ) { //generate content in json format
				var content = `{ "61286": { "1": "0x${pubKey}", "2": ${nonce}, "3": ${vote_purpose} }, "61285": { "1": "0x${signature}" } }`;
			} else if ( args['json-extended'] === true ) { //generate content in json format with additional fields
				var prvKeyHex = Buffer.from(prvKey.as_bytes()).toString('hex');
				var content = `{ "workMode": "${workMode}", "votePurpose": "${vote_purpose_description}", "signDataHex": "${sign_data_hex}", "signature": "${signature}", "secretKey": "${prvKeyHex}", "publicKey": "${pubKey}", `;
				content += `"output": { "cbor": "${deregistrationCBOR}", "json": { "61286": { "1": "0x${pubKey}", "2": ${nonce}, "3": ${vote_purpose} }, "61285": { "1": "0x${signature}" } } } }`;
			} else { //generate content in text format
				var content = `${deregistrationCBOR}`;
			}

			//output the content to the console or to a file
			var out_file = args['out-file'];
		        //if there is no --out-file parameter specified or the parameter alone (true) then output to the console
			if ( typeof out_file === 'undefined' || out_file === true ) { console.log(content); }
			else { //else try to write the content out to the given file
				try {
				fs.writeFileSync(out_file,content, 'utf8')
				// file written successfully
				} catch (error) { console.error(`${error}`); process.exit(1); }
			}

			//output the deregistrationCBOR to a binary file
			var out_cbor = args['out-cbor'];
		        //if there is a --out-cbor parameter specified then try to write output as a binary cbor file
			if ( typeof out_cbor === 'string' ) {
				try {
				var writeBuf = Buffer.from(deregistrationCBOR,'hex')
				fs.writeFileSync(out_cbor, writeBuf, 'binary')
				} catch (error) { console.error(`${error}`); process.exit(1); }
			}
			break;



                case "sign-cip88":  //SIGN REGISTRATION DATA IN CIP-86 MODE (Pool-ID-Registration)

			//get calidus public key -> store it in calidusPubKeyHex
			var key_file_hex = args['calidus-public-key'];
		        if ( typeof key_file_hex === 'undefined' || key_file_hex === true ) { console.error(`Error: Missing calidus public key parameter`); showUsage(workMode); }

			//read in the key from a file or direct hex
		        calidusPubKeyHex = readKey2hex(key_file_hex, 'public');

			//load the calidus public key for sanity check
			try {
			var calidusPubKey = CardanoWasm.PublicKey.from_bytes(Buffer.from(calidusPubKeyHex,'hex'));
			} catch (error) { console.error(`Error: ${error}`); process.exit(1); }

			//generate the calidus-id in hex and bech format
			var calidusIdHex = `a1${getHash(calidusPubKeyHex, 28)}`; //hash the calidus publicKey with blake2b_224 (28bytes digest length) and add the prebyte a1=CalidusPoolKey
			var calidusIdBech = bech32.encode("calidus", bech32.toWords(Buffer.from(calidusIdHex, "hex")), 128); //encode in bech32 with a raised limit to 128 words because of the longer hash (56bytes)

			//get secret key -> store it in prvKeyHex
			var key_file_hex = args['secret-key'];
		        if ( typeof key_file_hex === 'undefined' || key_file_hex === true ) { console.error(`Error: Missing secret key parameter`); showUsage(workMode); }

			//read in the key from a file or direct hex
		        prvKeyHex = readKey2hex(key_file_hex, 'secret', [ 'StakePoolSigning', 'StakePoolExtendedSigning' ] );

			//load the private key (normal or extended)
			try {
			if ( prvKeyHex.length <= 64 ) { var prvKey = CardanoWasm.PrivateKey.from_normal_bytes(Buffer.from(prvKeyHex, "hex")); }
						else { var prvKey = CardanoWasm.PrivateKey.from_extended_bytes(Buffer.from(prvKeyHex.substring(0,128), "hex")); } //use only the first 64 bytes (128 chars)
			} catch (error) { console.error(`Error: ${error}`); process.exit(1); }

			//generate the public key from the secret signing key
			var pubKeyHex = Buffer.from(prvKey.to_public().as_bytes()).toString('hex')

			//calculate the pool-id, which is just the hash of the pubKey
			var poolIdHex = getHash(pubKeyHex,28)
			var poolIdBech = bech32.encode("pool", bech32.toWords(Buffer.from(poolIdHex, "hex")), 128); //encode in bech32 with a raised limit to 128 words because of the longer hash (56bytes)

			//get the --nonce parameter
			var nonce = args['nonce'];
		        if ( typeof nonce === 'undefined' ) { var totalUtcSeconds = Math.floor(new Date().getTime() / 1000); nonce = 4492800 + (totalUtcSeconds - 1596059091) }  //if not defined, set it to the slotHeight of cardano-mainnet
		        else if ( typeof nonce !== 'number' || nonce === true || nonce < 0 ) { console.error(`Error: Please specify a --nonce parameter with an unsigned integer value > 0, or remove the parameter so the mainnet slotHeight will be calculated from current time`); process.exit(1); }

			//construct the payload map
			var payloadMap = new Map().set(1,[ 1, Buffer.from(poolIdHex,'hex') ]).set(2,[]).set(3,[2]).set(4,nonce).set(7, Buffer.from(calidusPubKeyHex,'hex'));

			//convert it to a cbor hex string
			var payloadCborHex = Buffer.from(cbor.encode(payloadMap)).toString('hex');

			//hash the delegationCBOR hex string
			var payloadCborHash = getHash(payloadCborHex);


			//sign the payloadCborHash with the private key in CIP8 mode
			try {
				var ret = signCIP8('sign-cip8',
					[ '--cip8',
//					  '--hashed',
					  '--data-hex', payloadCborHash,
					  '--secret-key', prvKeyHex,
					  '--address', poolIdHex ] );
			} catch (error) { console.error(`Error: CIP-8 signing error ${error.msg}`); process.exit(1); }

			//convert the cose_sign1 into a standard map
			var coseSign1Map = cbor.decode(ret.cose_sign1_cbor_hex);

			//set the { "hashed": false } entry in the array at index 1 to 0 so it can be used in tx_metadata (no boolean values allowed)
			coseSign1Map[1] = 0;
//			coseSign1Map[1] = 1;

			//convert the cose_key into a standard map
			var coseKeyMap = cbor.decode(ret.cose_key_cbor_hex)

			//construct the witness map within an array, we only generate one witness set here
			var witnessMap = [ new Map().set(1, coseKeyMap).set(2, coseSign1Map) ];

			//construct registration map
			var registrationMap = new Map().set(867, new Map().set(0, 2).set(1, payloadMap).set(2, witnessMap));

			//convert it to a cbor hex string
			var registrationCborHex = Buffer.from(cbor.encode(registrationMap)).toString('hex');

			//compose the content for the output as JSON registration, extended JSON data or plain registrationCBOR
			if ( args['json'] === true ) { //generate content in json format

				var content = mapToJs(registrationMap)

			} else if ( args['json-extended'] === true ) { //generate content in json format with additional fields

				var content = `{ "workMode": "${workMode}", "poolIdHex": "${poolIdHex}", "poolIdBech": "${poolIdBech}",`;
				content += `"calidusPublicKey": "${calidusPubKeyHex}", "calidusIdHex": "${calidusIdHex}", "calidusIdBech": "${calidusIdBech}",`;
				content += `"secretKey": "${prvKeyHex}", "publicKey": "${pubKeyHex}", "nonce": ${nonce}, "payloadCbor": "${payloadCborHex}",`;
				content += `"payloadHash": "${payloadCborHash}", "coseSign1Hex": "${ret.cose_sign1_cbor_hex}", "coseKeyHex": "${ret.cose_key_cbor_hex}",`;
				content += `"output": { "cbor": "${registrationCborHex}", "json": ${mapToJs(registrationMap)} } }`;

			} else { //generate content in text format
				var content = `${registrationCborHex}`;
			}

			//output the content to the console or to a file
			var out_file = args['out-file'];
		        //if there is no --out-file parameter specified or the parameter alone (true) then output to the console
			if ( typeof out_file === 'undefined' || out_file === true ) { console.log(content); }
			else { //else try to write the content out to the given file
				try {
				fs.writeFileSync(out_file,content, 'utf8')
				// file written successfully
				} catch (error) { console.error(`${error}`); process.exit(1); }
			}

			//output the registrationCBOR to a binary file
			var out_cbor = args['out-cbor'];
		        //if there is a --out-cbor parameter specified then try to write output as a binary cbor file
			if ( typeof out_cbor === 'string' ) {
				try {
				var writeBuf = Buffer.from(registrationCborHex,'hex')
				fs.writeFileSync(out_cbor, writeBuf, 'binary')
				} catch (error) { console.error(`${error}`); process.exit(1); }
			}

			break;



                case "verify":	//VERIFY DATA IN DEFAULT MODE

			//get data-hex to verify -> store it in verify_data_hex
			var verify_data_hex = args['data-hex'];
		        if ( typeof verify_data_hex === 'undefined' || verify_data_hex === true ) {

				//no data-hex parameter present, lets try the data parameter
				var verify_data = args['data'];
			        if ( typeof verify_data === 'undefined' || verify_data === true ) {

					//no data parameter present, lets try the data-file parameter
					var verify_data_file = args['data-file'];
				        if ( typeof verify_data_file === 'undefined' || verify_data_file === true ) {console.error(`Error: Missing data / data-hex / data-file to verify`); showUsage(workMode);}

					//data-file present lets read the file and store it hex encoded in verify_data_hex
					try {
						verify_data_hex = fs.readFileSync(verify_data_file,null).toString('hex'); //reads the file as binary
					} catch (error) { console.error(`Error: Can't read data-file '${verify_data_file}'`); process.exit(1); }

				} else {
				//data parameter present, lets convert it to hex and store it in the verify_data_hex variable
				verify_data_hex = Buffer.from(verify_data).toString('hex');
				}

			}
		        verify_data_hex = trimString(verify_data_hex.toLowerCase());

			//check that the given data is a hex string
			if ( ! regExpHex.test(verify_data_hex) ) { console.error(`Error: Data to verify is not a valid hex string`); process.exit(1); }

			//get the signature to verify -> store it in signature
			var signature = args['signature'];
		        if ( typeof signature === 'undefined' || signature === true ) { console.error(`Error: Missing signature`); showUsage(workMode); }
		        signature = trimString(signature.toLowerCase());

			//check if that the given signature is a hex string, if not check if its a bech encoded signature
			if ( ! regExpHex.test(signature) ) {
				try {
					signature = Buffer.from(bech32.fromWords(bech32.decode(signature,128).words)).toString('hex');
				} catch (error) {console.error(`Error: Signature is not a valid hex string or a valid bech encoded signature`); process.exit(1);}
			}

			//get public key -> store it in public_key
			var key_file_hex = args['public-key'];
		        if ( typeof key_file_hex === 'undefined' || key_file_hex === true ) { console.error(`Error: Missing public key parameter`); showUsage(workMode); }

			//read in the key from a file or direct hex
		        public_key = readKey2hex(key_file_hex, 'public');

			//load the public key
			try {
			var publicKey = CardanoWasm.PublicKey.from_bytes(Buffer.from(public_key,'hex'));
			} catch (error) { console.error(`Error: ${error}`); process.exit(1); }

			//check the pubKey against an optionally provided bech32 address via the --address parameter
                        var address = args['address'];
                        if ( typeof address === 'string' ) { //do the check if the parameter is provided

				//read the address from a file or direct hex/bech. also do a match check against the public key
			        var verify_addr = readAddr2hex(address, public_key);

	                        if ( ! verify_addr.matchPubKey ) { //exit with an error if the address does not contain the pubKey hash
					console.error(`Error: The ${verify_addr.type} address '${verify_addr.addr}' does not belong to the provided public key.`); process.exit(1);
				}
			}

			//load the Ed25519Signature
			try {
			var ed25519signature = CardanoWasm.Ed25519Signature.from_hex(signature);
			} catch (error) { console.error(`Error: ${error}`); process.exit(1); }

			//do the verification
			var verified = publicKey.verify(Buffer.from(verify_data_hex,'hex'),ed25519signature);

			//compose the content for the output: signature data + public key
			if ( args['json'] === true ) { //generate content in json format
				var content = `{ "result": "${verified}" }`;
			} else if ( args['json-extended'] === true ) { //generate content in json format with additional fields
				var content = `{ "workMode": "${workMode}", "result": "${verified}", `;
				if ( verify_data_hex.length <= 2000000 ) { content += `"verifyDataHex": "${verify_data_hex}", `; } //only include the verify_data_hex if it is less than 2M of chars
				if ( typeof verify_addr !== 'undefined' ) { content += `"addressHex": "${verify_addr.hex}", "addressType": "${verify_addr.type}", "addressNetwork": "${verify_addr.network}", `; } //only include the verification address if provided
				content += `"signature": "${signature}", "publicKey": "${public_key}" }`;
			} else { //generate content in text format
				var content = `${verified}`;
			}

			//output the verification result to the console or to a file
			var out_file = args['out-file'];
		        //if there is no --out-file parameter specified or the parameter alone (true) then output to the console
			if ( typeof out_file === 'undefined' || out_file === true ) { console.log(content);} //Output to console
			else { //else try to write the content out to the given file
				try {
				fs.writeFileSync(out_file,content, 'utf8')
				// file written successfully
				} catch (error) { console.error(`${error}`); process.exit(1); }
			}

			//exit with the right exitcode
			if ( verified ) { process.exit(0); }  //TRUE
				   else { process.exit(1); }  //FALSE
			break;


                case "verify-cip8":  //VERIFY DATA IN CIP-8 MODE -> currently idential to CIP-30
                case "verify-cip30":  //VERIFY DATA IN CIP-30 MODE -> CIP-8 structure

			//call verification subfunction
			try {
				var result = verifyCIP8(workMode);  //no extra arguments than `workMode` means that the function takes the parameters from the main process call
			} catch (error) {
				console.error(`Error: ${error.msg}`);
				if ( error.showUsage ) { showUsage(workMode); }
				process.exit(1);
			}

			//output the verification result to the console or to a file
			var out_file = args['out-file'];
		        //if there is no --out-file parameter specified or the parameter alone (true) then output to the console
			if ( typeof out_file === 'undefined' || out_file === true ) { console.log(result.content);} //Output to console
			else { //else try to write the content out to the given file
				try {
				fs.writeFileSync(out_file,result.content, 'utf8')
				// file written successfully
				} catch (error) { console.error(`${error}`); process.exit(1); }
			}

			//exit with the right return-code depending on the `verified` boolean
			if ( result.verified ) { process.exit(0); }  //TRUE
					  else { process.exit(1); }  //FALSE

			break;


                case "keygen":  //KEY GENERATION
                case "keygen-cip36":
                case "keygen-ledger":
                case "keygen-trezor":

			//setup
			var XpubKeyHex = '', XpubKeyBech = '', vote_purpose = -1, drepIdHex = '', drepIdBech = '';
			var ccColdIdHex = '', ccColdIdBech = '', ccHotIdHex = '', ccHotIdBech = '';
			var prvKeyBech = '', pubKeyBech = '', poolIdHex = '', poolIdBech = '', derivation_type = '';
			var rootKeyHex = '';

			//get the path parameter, if ok set the derivation_path variable
			var derivation_path = args['path'];
		        if ( typeof derivation_path === 'string' && derivation_path != '' ) { //ok, a path was provided let check
				derivation_path = trimString(derivation_path.toUpperCase());
				var derivation_path_arg = derivation_path

				//predefined derivation paths via name
				switch (derivation_path) {
					case 'PAYMENT': derivation_path = '1852H/1815H/0H/0/0'; break;
					case 'STAKE': derivation_path = '1852H/1815H/0H/2/0'; break;
					case 'CIP36': derivation_path = '1694H/1815H/0H/0/0'; break;
					case 'DREP': derivation_path = '1852H/1815H/0H/3/0'; break;
					case 'CC-COLD': derivation_path = '1852H/1815H/0H/4/0'; break;
					case 'CC-HOT': derivation_path = '1852H/1815H/0H/5/0'; break;
					case 'POOL': derivation_path = '1853H/1815H/0H/0H'; break;
					case 'CALIDUS': derivation_path = '1852H/1815H/0H/0/0'; break;
				}

				if ( derivation_path.indexOf(`'`) > -1 ) { derivation_path = derivation_path.replace(/'/g,'H'); } //replace the ' char with a H char
				if ( ! regExpPath.test(derivation_path) ) { console.error(`Error: The provided derivation --path '${derivation_path}' does not match the right format! Example: 1852H/1815H/0H/0/0`); process.exit(1); }
			} else {
				var derivation_path = ''; //no path provided, set the derivation_path variable to be empty
				var derivation_path_arg = derivation_path
			}

			//load or overwrite derivation path if CIP36 vote keys are selected
			if ( args['cip36'] === true ) { var derivation_path = '1694H/1815H/0H/0/0' }


			//get mnemonics parameter, if ok set the mnemonics variable
			var mnemonics = args['mnemonics'];
		        if ( typeof mnemonics === 'string' && mnemonics != '' ) { //ok, mnemonics were provided let check
				mnemonics = trimMnemonic(mnemonics.toLowerCase());
				var mnemonicsWordCount = wordCount(mnemonics);
				if ( mnemonicsWordCount < 12 || mnemonicsWordCount > 24 ) { console.error(`Error: Please provide between 12 and 24 words for the --mnemonics.`); process.exit(1); }

				//calculate the entropy of the given mnemonic
				try {
					var entropy = Buffer.from(bip39.mnemonicToEntropy(mnemonics),'hex')
				} catch (error) { console.error(`Error: The provided mnemonics are not valid, please check the correct spelling. '${error}'`); process.exit(1); }

				//set the derivation path to the default if not already set before -> users expect that if you provide mnemonics that they are used. otherwise a normal "underived" keypair would be created
				if ( derivation_path == '' ) { derivation_path = '1852H/1815H/0H/0/0'; }

			} else { //no mnemonics provided, generate a random entropy and get the mnemonics from it

				var entropy = crypto.randomBytes(32); //new random entropy
				var mnemonics = bip39.entropyToMnemonic(entropy); //get the mnemonics from the entropy
				var mnemonicsWordCount = wordCount(mnemonics);

			}

			//check about a given extra passphrase
			var passphrase = args['passphrase'];
		        if ( typeof passphrase !== 'string' ) { passphrase = '' };

			//if there is no derivation_path set, than a simple normal ed25519 key (not derived) is requested
			if ( derivation_path == '' ) { //generate a simple ed25519 keypair

				try {
				        var rootKey = CardanoWasm.PrivateKey.generate_ed25519(); //generate a new ed25519 key
					var prvKeyHex = Buffer.from(rootKey.as_bytes()).toString('hex'); //private-secret key in hex format
					var pubKeyHex = Buffer.from(rootKey.to_public().as_bytes()).toString('hex'); //public key in hex format
				} catch (error) { console.error(`Error: Could not generate a new ed25519 keypair. '${error}'`); process.exit(1); }
				var entropy = '', mnemonics = '';

				//store the rootKey in hex format for output later on
				var rootKeyHex = Buffer.from(rootKey.as_bytes()).toString('hex');

			} else { //derivation path is present, so we derive the rootKey via mnemonics

					switch (workMode) {

						case "keygen-ledger": 	// generate a rootkey via ledger derivation method
									//console.log(`Generating rootkey from ledger method`);
									try {
										var rootKey = CardanoWasm.Bip32PrivateKey.from_bytes(generateLedgerMasterKey(mnemonics, passphrase));
									} catch (error) { console.error(`Error: Could not generate the rootKey for ledger type mnemonics. '${error}'`); process.exit(1); }
									derivation_type = 'ledger';
									break;

						case "keygen-trezor": 	// generate a rootkey via trezor derivation method
									//console.log(`Generating rootkey from trezor method`);
									switch (mnemonicsWordCount) {
										case 12:
										case 15:
										case 18: 	//for 12,15 or 18 words the derivation type of trezor is the normal icarus
												try {
													var rootKey = CardanoWasm.Bip32PrivateKey.from_bytes(masterKey = generateIcarusMasterKey(entropy, passphrase));
												} catch (error) { console.error(`Error: Could not generate the rootKey for trezor type 12/15/18words mnemonic. '${error}'`); process.exit(1); }
												derivation_type = 'icarus';
												break;

										case 24:	//for 24 words we have to deal with the trezor-bug first
												try {
													var newentropy = new Uint8Array([...entropy,binaryToByte(deriveChecksumBits(entropy))])
													var rootKey = CardanoWasm.Bip32PrivateKey.from_bytes(masterKey = generateIcarusMasterKey(newentropy, passphrase));
												} catch (error) { console.error(`Error: Could not generate the rootKey for trezor type 24words mnemonic. '${error}'`); process.exit(1); }
												derivation_type = 'trezor';
												break;

										default:	// there are only 12,15,18 or 24 words allowed with trezor, throw an error otherwise
												console.error(`Error: Could not generate the rootKey for icarus/normal type from the entropy/mnemonic. '${error}'`); process.exit(1);
												break;
									}
									break;

						default:	// defaults to normal icarus (wallet) derivation method
								try {
									var rootKey = CardanoWasm.Bip32PrivateKey.from_bip39_entropy(entropy,''); //generate a ed25519e key from the provided entropy(mnemonics)
								} catch (error) { console.error(`Error: Could not generate the rootKey for icarus/normal type from the entropy/mnemonic. '${error}'`); process.exit(1); }
								derivation_type = 'icarus';
								break;
					}

				//store the rootKey in hex format for output later on
				var rootKeyHex = Buffer.from(rootKey.as_bytes()).toString('hex');

				var pathArray = derivation_path.split('/');
				pathArray.forEach( (element, index) => {
					var numPath = 0;
					//check if last char is an H, if so, add the hardened offset value
					if ( element[element.length - 1] == 'H' ) {
						 numPath+=0x80000000; //hardened path add the 0x80000000 offset
						 element = element.slice(0,-1); //remove the last char 'H' so only a number is left
					}
					numPath += Number(element); //add+convert the element number
					//derive the path
					try {
						rootKey = rootKey.derive(numPath);
					} catch (error) { console.error(`Error: Could not derive the given path from the rootKey. '${error}'`); process.exit(1); }

					//get the Xpublickey after the 3rd derived path (index=2)
					if ( index == 2 ) {
						XpubKeyHex = Buffer.from(rootKey.to_public().as_bytes()).toString('hex'); //Xpublic key in hex format (64bytes)
						XpubKeyBech = bech32.encode("Xpub", bech32.toWords(Buffer.from(XpubKeyHex, "hex")), 128);
					}
				});


				//if derived, we always have an extended private secret key
				var prvKeyHex = Buffer.from(rootKey.to_128_xprv()).toString('hex'); //private-secret key in hex format (64bytes private + 32bytes public + 32bytes chaincode)
				//var prvKeyHex = Buffer.from(rootKey.to_raw_key().as_bytes()).toString('hex'); //private-secret key in hex format (64bytes) - not used here because its always an extended one

				//if the extra flag 'vkey-extended' is set, generate a 64byte public key. otherwise generate a 32byte public key
				if ( args['vkey-extended'] === true ) {
					var pubKeyHex = Buffer.from(rootKey.to_public().as_bytes()).toString('hex'); //public key in hex format (64bytes)
				} else {
					var pubKeyHex = Buffer.from(rootKey.to_public().as_bytes()).toString('hex').substring(0,64); //public key in hex format (cut it to a non-extended publickey, 32bytes)
				}

			}

			//generate the cbor representation of the private & public key
			var prvKeyCbor = cbor.encode(Buffer.from(prvKeyHex,'hex')).toString('hex')
			var pubKeyCbor = cbor.encode(Buffer.from(pubKeyHex,'hex')).toString('hex')


			//generate the content depending on the derivation path
			switch (derivation_path.substring(0,11)) {

				case '': //simple ed25519 keys

					var skeyContent = `{ "type": "PaymentSigningKeyShelley_ed25519", "description": "Payment Signing Key", "cborHex": "${prvKeyCbor}" }`;
					var vkeyContent = `{ "type": "PaymentVerificationKeyShelley_ed25519", "description": "Payment Verification Key", "cborHex": "${pubKeyCbor}" }`;
					break;


				case '1694H/1815H': //CIP36 voting keys

					//get the --vote-purpose parameter, set default = 0
					var vote_purpose_param = args['vote-purpose'];
				        if ( typeof vote_purpose_param === 'undefined' ) { vote_purpose = 0 }  //if not defined, set it to default=0
				        else if ( typeof vote_purpose_param === 'number' && vote_purpose_param >= 0 ) { vote_purpose = vote_purpose_param }
					else { console.error(`Error: Please specify a --vote-purpose parameter with an unsigned integer value >= 0`); process.exit(1); }

					//get a cleartext description of the purpose (shown in the --json-extended output)
					switch (vote_purpose) {
						case 0: var vote_purpose_description="Catalyst"; break;
						default: var vote_purpose_description="Unknown";
					}

					var skeyContent = `{ "type": "CIP36VoteExtendedSigningKey_ed25519", "description": "${vote_purpose_description} Vote Signing Key", "cborHex": "${prvKeyCbor}" }`;
					if ( args['vkey-extended'] === true ) {
						var vkeyContent = `{ "type": "CIP36VoteExtendedVerificationKey_ed25519", "description": "${vote_purpose_description} Vote Verification Key", "cborHex": "${pubKeyCbor}" }`;
					} else {
						var vkeyContent = `{ "type": "CIP36VoteVerificationKey_ed25519", "description": "${vote_purpose_description} Vote Verification Key", "cborHex": "${pubKeyCbor}" }`;
					}
					//generate the keys also in bech format
					var prvKeyBech = bech32.encode("cvote_sk", bech32.toWords(Buffer.from(prvKeyHex, "hex")), 256); //encode in bech32 with a raised limit to 256 words because of the extralong privatekey (128bytes)
					var pubKeyBech = bech32.encode("cvote_vk", bech32.toWords(Buffer.from(pubKeyHex, "hex")), 128); //encode in bech32 with a raised limit to 128 words because of the longer publickey (64bytes)
					break;


				case '1852H/1815H': //Extended Payment/Staking keys and also Drep keys

					//generate different key outputs depending on the path number field 4 (idx=3) 1H/2H/3H/4/5
					switch (derivation_path.split('/')[3]) {

						case '2': //path is a stake key

							var skeyContent = `{ "type": "StakeExtendedSigningKeyShelley_ed25519_bip32", "description": "Stake Signing Key", "cborHex": "${prvKeyCbor}" }`;

							if ( args['vkey-extended'] === true ) {
								var vkeyContent = `{ "type": "StakeExtendedVerificationKeyShelley_ed25519_bip32", "description": "Stake Verification Key", "cborHex": "${pubKeyCbor}" }`;
							} else {
								var vkeyContent = `{ "type": "StakeVerificationKeyShelley_ed25519", "description": "Stake Verification Key", "cborHex": "${pubKeyCbor}" }`;
							}
							break;


						case '3': //path is a drep key

							//generate the secret/private key formats
							var skeyContent = `{ "type": "DRepExtendedSigningKey_ed25519_bip32", "description": "Delegate Representative Signing Key", "cborHex": "${prvKeyCbor}" }`;
							var prvKeyBech = bech32.encode("drep_xsk", bech32.toWords(Buffer.from(prvKeyHex, "hex")), 256); //encode in bech32 with a raised limit to 256 words because of the extralong privatekey (128bytes)

							//also generate the drep id in hex and bech format
							var drepIdHex = getHash(pubKeyHex, 28); //hash the publicKey with blake2b_224 (28bytes digest length)
							var drepIdBech = bech32.encode("drep", bech32.toWords(Buffer.from(drepIdHex, "hex")), 128); //encode in bech32 with a raised limit to 128 words because of the longer hash (56bytes)

							//generate the public key formats
							if ( args['vkey-extended'] === true ) {
								var vkeyContent = `{ "type": "DRepExtendedVerificationKey_ed25519_bip32", "description": "Delegate Representative Verification Key", "cborHex": "${pubKeyCbor}" }`;
								var pubKeyBech = bech32.encode("drep_xvk", bech32.toWords(Buffer.from(pubKeyHex, "hex")), 128); //encode in bech32 with a raised limit to 128 words because of the longer publickey (64bytes)
							} else {
								var vkeyContent = `{ "type": "DRepVerificationKey_ed25519", "description": "Delegate Representative Verification Key", "cborHex": "${pubKeyCbor}" }`;
								var pubKeyBech = bech32.encode("drep_vk", bech32.toWords(Buffer.from(pubKeyHex, "hex")), 128); //encode in bech32 with a raised limit to 128 words because of the longer publickey (64bytes)
							}

							break;


						case '4': //path is a constitutional committee cold key

							//generate the secret/private key formats
							var skeyContent = `{ "type": "ConstitutionalCommitteeColdExtendedSigningKey_ed25519_bip32", "description": "Constitutional Committee Cold Extended Signing Key", "cborHex": "${prvKeyCbor}" }`;
							var prvKeyBech = bech32.encode("cc_cold_xsk", bech32.toWords(Buffer.from(prvKeyHex, "hex")), 256); //encode in bech32 with a raised limit to 256 words because of the extralong privatekey (128bytes)

							//also generate the cc id in hex and bech format
							var ccColdIdHex = getHash(pubKeyHex, 28); //hash the publicKey with blake2b_224 (28bytes digest length)
							var ccColdIdBech = bech32.encode("cc_cold", bech32.toWords(Buffer.from(ccColdIdHex, "hex")), 128); //encode in bech32 with a raised limit to 128 words because of the longer hash (56bytes)

							if ( args['vkey-extended'] === true ) {
								var vkeyContent = `{ "type": "ConstitutionalCommitteeColdExtendedVerificationKey_ed25519_bip32", "description": "Constitutional Committee Cold Extended Verification Key", "cborHex": "${pubKeyCbor}" }`;
								var pubKeyBech = bech32.encode("cc_cold_xvk", bech32.toWords(Buffer.from(pubKeyHex, "hex")), 128); //encode in bech32 with a raised limit to 128 words because of the longer publickey (64bytes)
							} else {
								var vkeyContent = `{ "type": "ConstitutionalCommitteeColdVerificationKey_ed25519", "description": "Constitutional Committee Cold Verification Key", "cborHex": "${pubKeyCbor}" }`;
								var pubKeyBech = bech32.encode("cc_cold_vk", bech32.toWords(Buffer.from(pubKeyHex, "hex")), 128); //encode in bech32 with a raised limit to 128 words because of the longer publickey (64bytes)
							}

							break;


						case '5': //path is a constitutional committee hot key

							//generate the secret/private key formats
							var skeyContent = `{ "type": "ConstitutionalCommitteeHotExtendedSigningKey_ed25519_bip32", "description": "Constitutional Committee Hot Extended Signing Key", "cborHex": "${prvKeyCbor}" }`;
							var prvKeyBech = bech32.encode("cc_hot_xsk", bech32.toWords(Buffer.from(prvKeyHex, "hex")), 256); //encode in bech32 with a raised limit to 256 words because of the extralong privatekey (128bytes)

							//also generate the cc id in hex and bech format
							var ccHotIdHex = getHash(pubKeyHex, 28); //hash the publicKey with blake2b_224 (28bytes digest length)
							var ccHotIdBech = bech32.encode("cc_hot", bech32.toWords(Buffer.from(ccHotIdHex, "hex")), 128); //encode in bech32 with a raised limit to 128 words because of the longer hash (56bytes)

							if ( args['vkey-extended'] === true ) {
								var vkeyContent = `{ "type": "ConstitutionalCommitteeHotExtendedVerificationKey_ed25519_bip32", "description": "Constitutional Committee Hot Extended Verification Key", "cborHex": "${pubKeyCbor}" }`;
								var pubKeyBech = bech32.encode("cc_hot_xvk", bech32.toWords(Buffer.from(pubKeyHex, "hex")), 128); //encode in bech32 with a raised limit to 128 words because of the longer publickey (64bytes)
							} else {
								var vkeyContent = `{ "type": "ConstitutionalCommitteeHotVerificationKey_ed25519", "description": "Constitutional Committee Hot Verification Key", "cborHex": "${pubKeyCbor}" }`;
								var pubKeyBech = bech32.encode("cc_hot_vk", bech32.toWords(Buffer.from(pubKeyHex, "hex")), 128); //encode in bech32 with a raised limit to 128 words because of the longer publickey (64bytes)
							}

							break;


						default: //looks like a payment key, but recheck the provided derivation path argument

							switch (derivation_path_arg) {

								case 'CALIDUS': //path is --path calidus -> generate the calidusID and special description for the skey/vkey content
									var calidusIdHex = `a1${getHash(pubKeyHex, 28)}`; //hash the publicKey with blake2b_224 (28bytes digest length) and add the prebyte a1=CalidusPoolKey
									var calidusIdBech = bech32.encode("calidus", bech32.toWords(Buffer.from(calidusIdHex, "hex")), 128); //encode in bech32 with a raised limit to 128 words because of the longer hash (56bytes)
									var keyFileDescription = "Calidus Pool"
									break;

								default: //standard payment key
									var keyFileDescription = "Payment"
									break;

							} //switch args['path']

							var skeyContent = `{ "type": "PaymentExtendedSigningKeyShelley_ed25519_bip32", "description": "${keyFileDescription} Signing Key", "cborHex": "${prvKeyCbor}" }`;
							if ( args['vkey-extended'] === true ) {
								var vkeyContent = `{ "type": "PaymentExtendedVerificationKeyShelley_ed25519_bip32", "description": "${keyFileDescription} Verification Key", "cborHex": "${pubKeyCbor}" }`;
							} else {
								var vkeyContent = `{ "type": "PaymentVerificationKeyShelley_ed25519", "description": "${keyFileDescription} Verification Key", "cborHex": "${pubKeyCbor}" }`;
							}
							break;

					} //switch (derivation_path.split('/')[3])
					break;


				case '1853H/1815H': //pool keys

					var skeyContent = `{ "type": "StakePoolExtendedSigningKey_ed25519_bip32", "description": "Stake Pool Operator Signing Key", "cborHex": "${prvKeyCbor}" }`;
					if ( args['vkey-extended'] === true ) {
						var vkeyContent = `{ "type": "StakePoolExtendedVerificationKey_ed25519_bip32", "description": "Stake Pool Operator Verification Key", "cborHex": "${pubKeyCbor}" }`;
					} else {
						var vkeyContent = `{ "type": "StakePoolVerificationKey_ed25519", "description": "Stake Pool Operator Verification Key", "cborHex": "${pubKeyCbor}" }`;
					}

					//also generate the pool id in hex and bech format
					var poolIdHex = getHash(pubKeyHex, 28); //hash the publicKey with blake2b_224 (28bytes digest length)
					var poolIdBech = bech32.encode("pool", bech32.toWords(Buffer.from(poolIdHex, "hex")), 128); //encode in bech32 with a raised limit to 128 words because of the longer hash (56bytes)

					//generate the keys also in bech format
					var prvKeyBech = bech32.encode("pool_sk", bech32.toWords(Buffer.from(prvKeyHex, "hex")), 256); //encode in bech32 with a raised limit to 256 words because of the extralong privatekey (128bytes)
					var pubKeyBech = bech32.encode("pool_vk", bech32.toWords(Buffer.from(pubKeyHex, "hex")), 128); //encode in bech32 with a raised limit to 128 words because of the longer publickey (64bytes)
					break;


				default: //generic ones

					var skeyContent = `{ "type": "ExtendedSigningKeyShelley_ed25519_bip32", "description": "Signing Key", "cborHex": "${prvKeyCbor}" }`;
					var vkeyContent = `{ "type": "ExtendedVerificationKeyShelley_ed25519_bip32", "description": "Verification Key", "cborHex": "${pubKeyCbor}" }`;

			} //switch (derivation_path.substring(0,11))


			//compose the content for the output as JSON, extended JSON data or plain hex
			if ( args['json'] === true ) { //generate content in json format
				var content = `{ "secretKey": "${prvKeyHex}", "publicKey": "${pubKeyHex}" }`;
			} else if ( args['json-extended'] === true ) { //generate content in json format with additional fields
				var content = `{ "workMode": "${workMode}"`
				if ( derivation_path != '' ) { content += `, "derivationPath": "${derivation_path}"`; }
				if ( derivation_type != '' ) { content += `, "derivationType": "${derivation_type}"`; }
				if ( vote_purpose > -1 ) { content += `, "votePurpose": "${vote_purpose_description} (${vote_purpose})"`; }
				if ( mnemonics != '' ) { content += `, "mnemonics": "${mnemonics}"`; }
				if ( passphrase != '' ) { content += `, "passphrase": "${passphrase}"`; }
				if ( rootKeyHex != '' ) { content += `, "rootKey": "${rootKeyHex}"`; }
				content += `, "secretKey": "${prvKeyHex}", "publicKey": "${pubKeyHex}"`;
				if ( XpubKeyHex != '' ) { content += `, "XpubKeyHex": "${XpubKeyHex}", "XpubKeyBech": "${XpubKeyBech}"`; }
				if ( drepIdHex != '' ) { content += `, "drepIdHex": "${drepIdHex}", "drepIdBech": "${drepIdBech}"`; }
				else if ( ccColdIdHex != '' ) { content += `, "ccColdIdHex": "${ccColdIdHex}", "ccColdIdBech": "${ccColdIdBech}"`; }
				else if ( ccHotIdHex != '' ) { content += `, "ccHotIdHex": "${ccHotIdHex}", "ccHotIdBech": "${ccHotIdBech}"`; }
				else if ( poolIdHex != '' ) { content += `, "poolIdHex": "${poolIdHex}", "poolIdBech": "${poolIdBech}"`; }
				else if ( calidusIdHex != '' ) { content += `, "calidusIdHex": "${calidusIdHex}", "calidusIdBech": "${calidusIdBech}"`; }
				if ( prvKeyBech != '' ) { content += `, "secretKeyBech": "${prvKeyBech}", "publicKeyBech": "${pubKeyBech}"`; }
				content += `, "output": { "skey": ${skeyContent}, "vkey": ${vkeyContent} } }`
			} else { //generate content in text format
				var content = `${prvKeyHex} ${pubKeyHex}`;
			}

			//output the content to the console or to a file
			var out_file = args['out-file'];
		        //if there is no --out-file parameter specified or the parameter alone (true) then output to the console
			if ( typeof out_file === 'undefined' || out_file === true ) { console.log(content); }
			else { //else try to write the content out to the given file
				try {
				fs.writeFileSync(out_file,content, 'utf8')
				// file written successfully
				} catch (error) { console.error(`${error}`); process.exit(1); }
			}

			//output a secret file (.skey)
			var out_skey = args['out-skey'];
		        //if there is a --out-skey parameter specified then try to write output the file
			if ( typeof out_skey === 'string' && out_skey != '' ) {
				try {
				fs.writeFileSync(out_skey,JSON.stringify(JSON.parse(skeyContent), null, 2) + '\n', 'utf8')
				// file written successfully
				} catch (error) { console.error(`${error}`); process.exit(1); }
			}

			//output a verification file (.vkey)
			var out_vkey = args['out-vkey'];
		        //if there is a --out-vkey parameter specified then try to write output the file
			if ( typeof out_vkey === 'string' && out_vkey != '' ) {
				try {
				fs.writeFileSync(out_vkey,JSON.stringify(JSON.parse(vkeyContent), null, 2) + '\n', 'utf8')
				// file written successfully
				} catch (error) { console.error(`${error}`); process.exit(1); }
			}

			break;


		case "canonize-cip100": //CANONIZE AND HASH JSONLD GOVERNANCE METADATA

			//lets try to load data from the data parameter
			var data = args['data'];
		        if ( typeof data === 'undefined' || data == '' ) {

				//no data parameter present, lets try the data-file parameter
				var data_file = args['data-file'];
			        if ( typeof data_file === 'undefined' || data_file == '' ) {console.error(`Error: Missing data / data-file to hash`); showUsage(workMode);}

				//data-file present lets try to read and parse the file
				try {
					var jsonld_data = JSON.parse(fs.readFileSync(data_file,'utf8')); //parse the given key as a json file
				} catch (error) { console.error(`Error: Can't read data-file '${data_file}' or not valid JSON-LD data`); process.exit(1); }

			} else {
			//data parameter present, lets see if its valid json data
				try {
					var jsonld_data = JSON.parse(data);
				} catch (error) { console.error(`Error: Not valid JSON data (${error})`); process.exit(1); }
			}

			//JSON data is loaded into jsonld_data, now lets only use the @context and body key
			try {
				var jsonld_data = { "body" : jsonld_data["body"], "@context": jsonld_data["@context"] }; // var jsonld_data = {}; jsonld_data["body"] = jsonld_doc["body"]; jsonld_data["@context"] = jsonld_doc["@context"];
				if ( jsonld_data["body"] === undefined || jsonld_data["@context"] === undefined ) { console.error(`Error: JSON-LD must contain '@context' and 'body' data`); process.exit(1); }
			} catch (error) { console.error(`Error: Couldn't extract '@context' and 'body' JSON-LD data (${error})`); process.exit(1); }

			//Start the async canonize process, will get triggered via the .then part once the process finished
			jsonld.canonize(jsonld_data, {safe: false, algorithm: 'URDNA2015', format: 'application/n-quads'}).then( (canonized_data) =>
			        {
				//data was successfully canonized

					//output a canonized file if parameter is set
					var out_canonized_filename = args['out-canonized'];
				        //if there is a --out-canonized parameter specified then try to write out the file
					if ( typeof out_canonized_filename === 'string' && out_canonized_filename != '' ) {
						try {
							fs.writeFileSync(out_canonized_filename,canonized_data, 'utf8')
							// file written successfully
						} catch (error) { console.error(`${error}`); process.exit(1); }
					}

					//get the hash of the canonized data
					var canonized_hash = getHash(Buffer.from(canonized_data).toString('hex'));

					//compose the content for the output
					if ( args['json'] === true ) { //generate content in json format
						var content = `{ "canonizedHash": "${canonized_hash}" }`;
					} else if ( args['json-extended'] === true ) { //generate content in extended json format
						//split the canonized data into an array, remove the last element, do a loop for each element
						var canonized_array = [];
						canonized_data.split('\n').slice(0,-1).forEach( (element) => {
							canonized_array.push('"' + String(element).replace(/\\([\s\S])|(")/g,"\\$1$2") + '"'); //escape " with \" if it not already a \" while pushing new elements to the array
						})
						var content = `{ "workMode": "${workMode}", "canonizedHash": "${canonized_hash}", "body": ` + JSON.stringify(jsonld_data["body"]) + `, "canonizedBody": [ ${canonized_array} ] }`;
					} else { //generate content in text format
						var content = canonized_hash;
					}

					//output the content to the console or to a file
					var out_file = args['out-file'];
				        //if there is no --out-file parameter specified or the parameter alone (true) then output to the console
					if ( typeof out_file === 'undefined' || out_file == '' ) { console.log(content);} //Output to console
					else { //else try to write the content out to the given file
						try {
						fs.writeFileSync(out_file,content, 'utf8')
						// file written successfully
						} catch (error) { console.error(`${error}`); process.exit(1); }
					}

			        }).catch( (err) => {console.log(`Error: Could not canonize the data (${err.message})`);process.exit(1);});

			break;

		case "verify-cip100": //CANONIZE AND HASH JSONLD GOVERNANCE METADATA, CHECKS ALL THE AUTHORS SIGNATURES

			//load default variable
			var result = false //will be true if all authors signatures are valid/verified and no error occurs
			var errorStr = '' //will hold an explanation about an error
			var authors_array = [] //holds the authors for the output with there name and verified field

					//if the input to check was a file, read it in again to also provide the fileHash for it, if something goes wrong, don't show the anchorHash
				        if ( typeof data_file !== 'undefined' && data_file != '' ) {
							try {
								var fileHash = `, "fileHash": "` + getHash(binary_data) + `"`; //read in the file and hash it
							} catch (error) { anchorHash = ''; }
						} else if ( typeof data !== 'undefined' && data != '' ) { //input was data provided via the --data parameter
							try {
								var fileHash = `, "fileHash": "` + getHash(Buffer.from(data)) + `"`; //get the hash of the provided data
							} catch (error) { anchorHash = ''; }
						} else { anchorHash = ''; }



			//lets try to load data from the data parameter
			var data = args['data'];
		        if ( typeof data === 'undefined' || data == '' ) {

				//no data parameter present, lets try the data-file parameter
				var data_file = args['data-file'];
			        if ( typeof data_file === 'undefined' || data_file == '' ) {console.error(`Error: Missing data / data-file to verify`); showUsage(workMode);}

				//data-file present lets try to read and parse the file
				try {
					var binary_data = fs.readFileSync(data_file)
					var jsonld_input = JSON.parse(binary_data); //parse the binary data as a json file
				} catch (error) { console.error(`Error: Can't read data-file '${data_file}' or not valid JSON-LD data`); process.exit(1); }

				//calculate the fileHash
				var fileHash = getHash(binary_data)

			} else {
			//data parameter present, lets see if its valid json data
				try {
					var jsonld_input = JSON.parse(data);
				} catch (error) { console.error(`Error: Not valid JSON data (${error})`); process.exit(1); }

				//calculate the fileHash
				var fileHash = getHash(Buffer.from(data));
			}

			//JSON data is loaded into jsonld_input, now lets only use the @context and body key
			try {
				if ( jsonld_input["body"] === undefined || jsonld_input["@context"] === undefined ) { console.error(`Error: JSON-LD must contain '@context' and 'body' data`); process.exit(1); }
				var jsonld_data = { "body" : jsonld_input["body"], "@context": jsonld_input["@context"] }; // var jsonld_data = {}; jsonld_data["body"] = jsonld_doc["body"]; jsonld_data["@context"] = jsonld_doc["@context"];
			} catch (error) { console.error(`Error: Couldn't extract '@context' and 'body' JSON-LD data (${error})`); process.exit(1); }

			//Start the async canonize process, will get triggered via the .then part once the process finished
			jsonld.canonize(jsonld_data, {safe: false, algorithm: 'URDNA2015', format: 'application/n-quads'}).then( (canonized_data) =>
			        {
				//data was successfully canonized

					//get the hash of the canonized data
					if (jsonld_input["hashAlgorithm"] != 'blake2b-256') { console.error(`Error: unknown or missing hashAlgorithm - ${jsonld_input["hashAlgorithm"]}`); process.exit(1); }
					var canonized_hash = getHash(Buffer.from(canonized_data).toString('hex'));

					//do all the testing now in the verifyAuthors block
					verifyAuthors: {

						//check that the authors entry is present , if not break with an errordescription
						if ( jsonld_input["authors"] === undefined ) { errorStr='missing authors field'; break verifyAuthors; }
						var jsonld_authors = jsonld_input["authors"];
						//check that the authors entry is an array
						if ( typeof jsonld_authors !== 'object' || jsonld_authors instanceof Array == false ) { errorStr='authors entry is not an array'; break verifyAuthors; }
						//check that the number of authors is not zero
						if ( jsonld_authors.length == 0) { errorStr='no authors in the authors-array'; break verifyAuthors; }
						//check each authors array entry
						jsonld_authors.every( authorEntry => {
							var authorName = authorEntry["name"]; if (typeof authorName !== 'string') { errorStr='authors.name entry is missing or not a string'; return false; }

							var authorWitness = authorEntry["witness"]; if (typeof authorWitness !== 'object') { errorStr='authors.witness entry is missing or not a json object'; return false; }
							var authorWitnessAlgorithm = authorWitness["witnessAlgorithm"];	if (typeof authorWitnessAlgorithm !== 'string') { errorStr='authors.witness entry is missing or not a string'; return false; }

							var authorWitnessPublicKey = authorWitness["publicKey"]; if (typeof authorWitnessPublicKey !== 'string' || ! regExpHex.test(authorWitnessPublicKey) ) { errorStr=`authors.witness.publickey entry for '${authorName}' is not a valid hex-string`; return false; }
							//load the public key
							try {
								var publicKey = CardanoWasm.PublicKey.from_bytes(Buffer.from(authorWitnessPublicKey,'hex'));
							} catch (error) { errorStr=`authors.witness.publickey entry for '${authorName}' error ${error}`; return false; }

							//check if there is a duplicated entry already for that public key
							var hasDuplicates = authors_array.some( element => { return element["publicKey"] === authorWitnessPublicKey });
							if (hasDuplicates) { errorStr=`authors.witness.publickey entry for '${authorName}' has duplicates`; return false; }

							var authorWitnessSignature = authorWitness["signature"]; if (typeof authorWitnessSignature !== 'string' || ! regExpHex.test(authorWitnessSignature) ) { errorStr=`authors.witness.signature entry for '${authorName}' is not a valid hex-string`; return false; }

							var verified = false;

							//check now the different algorithm types - currently we support 'ed25519' and 'CIP-0008/CIP-0030'
							switch (authorWitnessAlgorithm) {

								case 'ed25519': //witness is signed with the standard ed25519 algorithm

									//load the Ed25519Signature
									try {
										var ed25519signature = CardanoWasm.Ed25519Signature.from_hex(authorWitnessSignature);
									} catch (error) { errorStr=`authors.witness.signature entry for '${authorName}' error ${error}`; return false; }
									//do the verification
									var verified = publicKey.verify(Buffer.from(canonized_hash,'hex'),ed25519signature);
									break;

								case 'CIP-0008': //witness is signed with the CIP-0008 (signData) algorithm
								case 'CIP-0030': //witness is signed with the CIP-0030 (signData) algorithm (deprecated)

									//verify the Signature
									try {
										var ret = verifyCIP8('verify-cip8',
													[ '--cip8',
													  '--cose-sign1', authorWitnessSignature,
													  '--cose-key', `a4010103272006215820${authorWitnessPublicKey}`, //prefix the publickey with the standard parameters for CIP0030
													  '--data-hex', canonized_hash ] );
									} catch (error) { errorStr=`authors.witness.signature entry for '${authorName}' error ${error.msg}`; return false; }
									var verified = ret.verified;
									break;

								default: //no supported algorithm found or its missing
									errorStr=`authors.witness.algorithm entry for '${authorName}' is missing or not supported. value='${authorWitnessAlgorithm}'`; return false;
									break;

							} //switch authorWitnessAlgorithm

							//check if there at least one not verified witness
							if (!verified) { errorStr=`at least one invalid signature found`; }

							//add it to the array of authors
							var authorArrayEntry = { "name" : authorName, "valid" : verified, "algorithm" : authorWitnessAlgorithm, "publicKey" : authorWitnessPublicKey, "signature" : authorWitnessSignature };
							authors_array.push(authorArrayEntry);

							//return=true -> go to the next entry
							return true;
						})

					}

					if ( errorStr == '' ) { result = true; }

					//compose the content for the output
					if ( args['json'] === true ) { //generate content in json format
						var content = `{ "result": ${result}, "errorMsg": "${errorStr}", "authors": ` + JSON.stringify(authors_array) + `, "fileHash": "${fileHash}" }`;
					} else if ( args['json-extended'] === true ) { //generate content in extended json format
						//split the canonized data into an array, remove the last element, do a loop for each element
						var canonized_array = [];
						canonized_data.split('\n').slice(0,-1).forEach( (element) => {
							canonized_array.push('"' + String(element).replace(/\\([\s\S])|(")/g,"\\$1$2") + '"'); //escape " with \" if it not already a \" while pushing new elements to the array
						})
						var content = `{ "workMode": "${workMode}", "result": ${result}, "errorMsg": "${errorStr}", "authors": ` + JSON.stringify(authors_array) + `, "canonizedHash": "${canonized_hash}", "fileHash": "${fileHash}", "body": ` + JSON.stringify(jsonld_data["body"]) + `, "canonizedBody": [ ${canonized_array} ] }`;
					} else { //generate content in text format
						var content = result;
					}

					//output the content to the console or to a file
					var out_file = args['out-file'];
				        //if there is no --out-file parameter specified or the parameter alone (true) then output to the console
					if ( typeof out_file === 'undefined' || out_file == '' ) { console.log(content);} //Output to console
					else { //else try to write the content out to the given file
						try {
						fs.writeFileSync(out_file,content, 'utf8')
						// file written successfully
						} catch (error) { console.error(`${error}`); process.exit(1); }
					}

			        }).catch( (err) => {console.log(`Error: Could not verify the data (${err.message})`);process.exit(1);});

			break;


		case "sign-cip100": //CANONIZE AND HASH JSONLD GOVERNANCE METADATA, SIGN THE DOCUMENT AND ADD AUTHORS

			//load default variable
			var authors_array = [] //holds the authors for the output with there name and verified field
			var all_authors_publickey_array = [] //holds a list of all publickeys of the authors

			//get signing key -> store it in sign_key
			var key_file_hex = args['secret-key'];
		        if ( typeof key_file_hex === 'undefined' || key_file_hex === true ) { console.error(`Error: Missing secret key parameter`); showUsage(workMode); }

			//read in the key from a file or direct hex
		        sign_key = readKey2hex(key_file_hex, 'secret');

			//load the private key (normal or extended)
			try {
			if ( sign_key.length <= 64 ) { var prvKey = CardanoWasm.PrivateKey.from_normal_bytes(Buffer.from(sign_key, "hex")); }
						else { var prvKey = CardanoWasm.PrivateKey.from_extended_bytes(Buffer.from(sign_key.substring(0,128), "hex")); } //use only the first 64 bytes (128 chars), rest is publicKey + chainCode
			} catch (error) { console.error(`Error: ${error}`); process.exit(1); }

			//generate the public key from the secret key for external verification
			var pubKey = Buffer.from(prvKey.to_public().as_bytes()).toString('hex')

			//get author name -> store it in add_author_name
			var add_author_name = args['author-name'];
		        if ( typeof add_author_name === 'undefined' || add_author_name === true || add_author_name == '' ) { console.error(`Error: Missing author name parameter`); showUsage(workMode); }

			//FIRST, we verify the input JSONLD File

			//lets try to load data from the data parameter
			var data = args['data'];
		        if ( typeof data === 'undefined' || data == '' ) {

				//no data parameter present, lets try the data-file parameter
				var data_file = args['data-file'];
			        if ( typeof data_file === 'undefined' || data_file == '' ) {console.error(`Error: Missing data / data-file to hash`); showUsage(workMode);}

				//data-file present lets try to read and parse the file
				try {
					var jsonld_input = JSON.parse(fs.readFileSync(data_file,'utf8')); //parse the given key as a json file
				} catch (error) { console.error(`Error: Can't read data-file '${data_file}' or not valid JSON-LD data`); process.exit(1); }

			} else {
			//data parameter present, lets see if its valid json data
				try {
					var jsonld_input = JSON.parse(data);
				} catch (error) { console.error(`Error: Not valid JSON data (${error})`); process.exit(1); }
			}

			//JSON data is loaded into jsonld_input, now lets only use the @context and body key
			try {
				if ( jsonld_input["body"] === undefined || jsonld_input["@context"] === undefined ) { console.error(`Error: JSON-LD must contain '@context' and 'body' data`); process.exit(1); }
				var jsonld_data = { "body" : jsonld_input["body"], "@context": jsonld_input["@context"] }; // var jsonld_data = {}; jsonld_data["body"] = jsonld_doc["body"]; jsonld_data["@context"] = jsonld_doc["@context"];
			} catch (error) { console.error(`Error: Couldn't extract '@context' and 'body' JSON-LD data (${error})`); process.exit(1); }

			//Start the async canonize process, will get triggered via the .then part once the process finished
			jsonld.canonize(jsonld_data, {safe: false, algorithm: 'URDNA2015', format: 'application/n-quads'}).then( (canonized_data) =>
			        {
				//data was successfully canonized

					//get the hash of the canonized data
					if (jsonld_input["hashAlgorithm"] != 'blake2b-256') { console.error(`Error: unknown or missing hashAlgorithm - ${jsonld_input["hashAlgorithm"]}`); process.exit(1); }
					var canonized_hash = getHash(Buffer.from(canonized_data).toString('hex'));

					//sign the data
					try {
						var signedBytes = prvKey.sign(Buffer.from(canonized_hash, 'hex')).to_bytes();
						var signature = Buffer.from(signedBytes).toString('hex');
					} catch (error) { console.error(`Error: ${error}`); process.exit(1); }

					//OK, at this point we have canonized and hash the @context&body content, also we have checked that the hashAlgorithm is correct
					//now lets check the authors field. if present, load it and check signatures that may be already present, if we detect a wrong one, exit with an error

					//do all the testing now in the verifyAuthors block
					verifyAuthors: {

						//check that the authors entry is present , if not make a blank array and exit
						if ( jsonld_input["authors"] === undefined ) { break verifyAuthors; }
						var jsonld_authors = jsonld_input["authors"];
						//check that the authors entry is an array
						if ( typeof jsonld_authors !== 'object' || jsonld_authors instanceof Array == false ) { econsole.error(`Error: authors entry is not an array`); process.exit(1); }
						//check each authors array entry
						jsonld_authors.every( authorEntry => {
							var authorName = authorEntry["name"]; if (typeof authorName !== 'string') { console.error(`Error: authors.name entry is not an string`); process.exit(1); }

							var authorWitness = authorEntry["witness"]; if (typeof authorWitness !== 'object') { console.error(`Error: authors.witness entry is missing or not a json object`); process.exit(1); }
							var authorWitnessAlgorithm = authorWitness["witnessAlgorithm"];	if (typeof authorWitnessAlgorithm !== 'string') { console.error(`Error: authors.witness.algorithm entry for '${authorName}' is missing or not a string`); process.exit(1); }

							var authorWitnessPublicKey = authorWitness["publicKey"]; if (typeof authorWitnessPublicKey !== 'string' || ! regExpHex.test(authorWitnessPublicKey) ) { console.error(`Error: authors.witness.publickey entry for '${authorName}' is not a valid hex-string`); process.exit(1); }
							//load the public key
							try {
								var publicKey = CardanoWasm.PublicKey.from_bytes(Buffer.from(authorWitnessPublicKey,'hex'));
							} catch (error) { errorStr=`authors.witness.publickey entry for '${authorName}' error ${error}`; return false; }

							//check if the current authors publicKey is the same as the one we wanna add
							if ( authorWitnessPublicKey == pubKey ) {
								switch (args['replace']) {
									case true: 	return true; break;  //publickey entry is the same, we wanna replace it with the new entry -> go to the next authors entry and don't add it to the existing list
									case false:	console.error(`Error: authors.witness.publickey entry for '${authorName}' is the same as the one you wanna add. please use the flag --replace if you wanna replace the entry`); process.exit(1); break;
								}
							}

							//check if there is a duplicated entry already for that public key
							var hasDuplicates = authors_array.some( element => { return element["publicKey"] === authorWitnessPublicKey });
							if (hasDuplicates) { console.error(`Error: authors.witness.publickey '${authorWitnessPublicKey}' in author '${authorName}' has duplicated entries! public keys must be unique, please remove duplicates first.`); process.exit(1); }

							var authorWitnessSignature = authorWitness["signature"]; if (typeof authorWitnessSignature !== 'string' || ! regExpHex.test(authorWitnessSignature) ) { console.error(`Error: authors.witness.signature entry for '${authorName}' is not a valid hex-string`); process.exit(1); }

							var verified = false;

							//check now the different algorithm types - currently we support 'ed25519' and 'CIP-0008'
							switch (authorWitnessAlgorithm) {

								case 'ed25519': //witness is signed with the standard ed25519 algorithm

									//load the Ed25519Signature
									try {
										var ed25519signature = CardanoWasm.Ed25519Signature.from_hex(authorWitnessSignature);
									} catch (error) { console.error(`Error: authors.witness.signature entry for '${authorName}' error ${error}`); process.exit(1); }
									//do the verification
									var verified = publicKey.verify(Buffer.from(canonized_hash,'hex'),ed25519signature);
									break;

								case 'CIP-0008': //witness is signed with the CIP-0008 (signData) algorithm

									//verify the Signature
									try {
										var ret = verifyCIP8('verify-cip8',
													[ '--cip8',
													  '--cose-sign1', authorWitnessSignature,
													  '--cose-key', `a4010103272006215820${authorWitnessPublicKey}`, //prefix the publickey with the standard parameters for CIP0030
													  '--data-hex', canonized_hash ] );
									} catch (error) { console.error(`Error: authors.witness.signature entry for '${authorName}' error ${error.msg}`); process.exit(1); }
									var verified = ret.verified;
									break;

								default: //no supported algorithm found or its missing
									console.error(`Error: authors.witness.algorithm entry for '${authorName}' is missing or not supported. value='${authorWitnessAlgorithm}'`); process.exit(1);
									break;

							} //switch authorWitnessAlgorithm

							//at this point, the existing author has been verified, add it to the array of authors
							var authorArrayEntry = { "name" : authorName,  "witness": { "witnessAlgorithm": authorWitnessAlgorithm, "publicKey" : authorWitnessPublicKey, "signature" : authorWitnessSignature } };
							authors_array.push(authorArrayEntry);

							//return=true -> go to the next entry
							return true;
						})

					}

					//we are finished with the authors verification, also we have already signed the canonized_hash
					var authorArrayEntry = { "name" : add_author_name, "witness": { "witnessAlgorithm": "ed25519", "publicKey" : pubKey, "signature" : signature } };
					authors_array.push(authorArrayEntry);

					//set the authors field in the JSONLD content
					jsonld_input["authors"] = authors_array;

					var content = JSON.stringify(jsonld_input, null, 2);

					//output the content to the console or to a file
					var out_file = args['out-file'];
				        //if there is no --out-file parameter specified or the parameter alone (true) then output to the console
					if ( typeof out_file === 'undefined' || out_file == '' ) { console.log(content);} //Output to console
					else { //else try to write the content out to the given file
						try {
						fs.writeFileSync(out_file,content, 'utf8')
						// file written successfully
						var anchorHash = getHash(Buffer.from(content));
						console.log(`{ "workMode": "${workMode}", "outFile": "${out_file}", "anchorHash": "${anchorHash}" }`);
						} catch (error) { console.error(`${error}`); process.exit(1); }
					}

			        }).catch( (err) => {console.log(`Error: Could not sign the data (${err.message})`);process.exit(1);});

			break;


		case "verify-cip88": //VERIFY DATA IN CIP88v2 (Calidus-Pool-Key)

			//lets try to load data from the data parameter in json format
			var data = args['data'];
		        if ( typeof data === 'string' && data != '' ) {	//data parameter present, lets see if its valid json data
				try {
					var jsonObject = JSON.parse(data);
					//convert the json object into a map object
					var dataMap = jsToMap(jsonObject);
				} catch (error) { console.error(`Error: Not valid JSON data (${error}) provided via the --data parameter`); process.exit(1); }

			}

			//no dataMap yet, lets try the data-file parameter
			if ( ! dataMap ) {
				var data_file = args['data-file'];
			        if ( typeof data_file === 'string' && data_file != '' ) {
					//data-file present lets try to read and parse the file as json
					try {
						var jsonObject = JSON.parse(fs.readFileSync(data_file,'utf8')); //parse the given file as a json file
						//convert the json object into a map object
						var dataMap = jsToMap(jsonObject);
					} catch (error) { console.error(`Error: Can't read data-file '${data_file}' or not valid JSON data`); process.exit(1); }
				} //data-file
			} //dataMap

			//no dataMap yet, lets try the data-hex parameter
			if ( ! dataMap ) {
				var data_hex = args['data-hex'];
			        if ( typeof data_hex === 'string' && regExpHex.test(data_hex.toLowerCase()) ) {
					//data-hex present lets try decode it from cbor
					try {
						var dataMap = cbor.decode(data_hex.toLowerCase()); //decode the given hex data as cbor
					} catch (error) { console.error(`Error: Can't cbor decode the given data-hex (${error})`); process.exit(1); }
				} //data-file
			} //dataMap

			//throw an error if we still have not dataMap to work with
			if ( ! dataMap ) {console.error(`Error: Missing data / data-hex / data-file to verify`); showUsage(workMode);}

			//we have the data to verify loaded into dataMap now, this is a Map object

			//do a rough sanity check on the key map entries
			if ( ! dataMap.has(867) || dataMap.get(867).size < 3 ) { console.error(`Error: Data to verify has no map label 867 or not enough entries`); process.exit(1); }
			else if ( isNaN(dataMap.get(867).get(0)) || dataMap.get(867).get(0) < 2 ) { console.error(`Error: Map key 0 (version) is not set to 2 or above`); process.exit(1); }
			else if ( ! dataMap.get(867).has(1) || dataMap.get(867).get(1).size < 5 ) { console.error(`Error: Map key 1 (payload) is missing or does not have at least 5 entries`); process.exit(1); }
			else if ( ! dataMap.get(867).has(2) || ! dataMap.get(867).get(2) instanceof Array || dataMap.get(867).get(2).length != 1 ) { console.error(`Error: Map key 2 (witness) is missing or is not an array with a single entry (only one witness supported currently)`); process.exit(1); }

			//get the payload_map and do deeper checks on it
			var payloadMap = dataMap.get(867).get(1)
			if ( !payloadMap.has(1) || !payloadMap.has(2) || !payloadMap.has(3) || !payloadMap.has(4) || !payloadMap.has(7) ) { console.error(`Error: Payload map does not have all needed keys 1,2,3,4 & 7`); process.exit(1); }
			else if ( ! payloadMap.get(1) instanceof Array || payloadMap.get(1)[0] != 1 ) { console.error(`Error: PayloadMap key 1 (registraction-scope) is not an array or not of type pool-scope(1)`); process.exit(1); }
			else if ( ! payloadMap.get(3) instanceof Array || isNaN(payloadMap.get(3)[0]) || payloadMap.get(3)[0] != 2) { console.error(`Error: PayloadMap key 3 (validation method) is not an array and/or not set to [2] -> CIP-0008`); process.exit(1); }
			else if ( isNaN(payloadMap.get(4)) ) { console.error(`Error: PayloadMap key 4 (nonce) is not a uint number`); process.exit(1); }
			else if ( ! Buffer.isBuffer(payloadMap.get(7)) || payloadMap.get(7).length != 32 ) { console.error(`Error: PayloadMap key 7 (calidus-public-key) is not a hex bytearray/buffer of length 32`); process.exit(1); }

			//get the poolid from the scope=1 content and check that its a bytearray with the correct length
			var scopePoolId = payloadMap.get(1)[1] //   [ 1 , h'(poolid-hex)' ]
			if ( ! Buffer.isBuffer(scopePoolId) || scopePoolId.length != 28 ) { console.error(`Error: Pool-ID part in PayloadMap key 1 (registration-scope) is not a hex bytearray/buffer of length 28`); process.exit(1); }
			var scopePoolIdHex =  scopePoolId.toString('hex')

                        //load the calidus public key for sanity check
                        try {
                        	var calidusPubKey = CardanoWasm.PublicKey.from_bytes(payloadMap.get(7));
				var calidusPubKeyHex = payloadMap.get(7).toString('hex')
                        } catch (error) { console.error(`Error: PayloadMap key 7 (calidus-public-key) -> ${error}`); process.exit(1); }

			//ok, the payloadMap should be fine, lets generate the cbor representation of it and also the hash for the message verification
			var payloadCborHex = cbor.encode(payloadMap).toString('hex');
			var payloadCborHash = getHash(payloadCborHex);

			//get the witness_map of the FIRST entry and do deeper checks on it
			var witnessMap = dataMap.get(867).get(2)[0]
			if ( ! witnessMap.has(1) || ! witnessMap.has(2) ) { console.error(`Error: Witness entry does not have the needed keys 1 & 2`); process.exit(1); }
			else if ( witnessMap.has(0) && witnessMap.get(0) != 0 ) { console.error(`Error: Witness entry key 0 (Witness Type Identifier) is not 0(COSE_Witness)`); process.exit(1); }

			//get the COSE_Key and COSE_Sign1 part
			var coseKeyMap = witnessMap.get(1)
			var coseSign1Map = witnessMap.get(2)

			//get the public key out of the coseKeyMap
			if ( ! Buffer.isBuffer(coseKeyMap.get(-2)) || coseKeyMap.get(-2).length != 32) { console.error(`Error: coseKeyMap key -2 (public key) is not a hex bytearray/buffer of length 32`); process.exit(1); }
                        //load the signing public key for sanity check
                        try {
                        	var pubKey = CardanoWasm.PublicKey.from_bytes(coseKeyMap.get(-2));
				var pubKeyHex = coseKeyMap.get(-2).toString('hex')
				var pubKeyPoolIdHex = getHash(pubKeyHex,28)  //the poolid that resolved from the used witnessPublicKey
				if ( scopePoolIdHex != pubKeyPoolIdHex ) { console.error(`Error: scope-PoolID(${scopePoolIdHex}) and witnessPublicKey-PoolID(${pubKeyPoolIdHex}) are not the same`); process.exit(1); }
                        } catch (error) { console.error(`Error: coseKeyMap key -2 (public key) -> ${error}`); process.exit(1); }

			//get the used poolId from the coseSign1Map[0]
			if ( ! Buffer.isBuffer(coseSign1Map[0]) || coseSign1Map[0].length != 41 ) { console.error(`Error: coseSign1Map[0] (protected header cbor) is not a hex bytearray/buffer of length 41`); process.exit(1); }
			try {
				var coseProtectedHeaderMap = cbor.decode(coseSign1Map[0])
				var cosePoolIdHex = coseProtectedHeaderMap.get("address").toString('hex')
				if ( scopePoolIdHex != cosePoolIdHex ) { console.error(`Error: scope-PoolID(${scopePoolIdHex}) and cose-PoolID(${cosePoolIdHex}) are not the same`); process.exit(1); }
			} catch (error) { console.error(`Error: Can't cbor decode the given COSE_Sign1 protected header (${error})`); process.exit(1); }

			if ( isNaN(coseSign1Map[1]) ) { console.error(`Error: coseSign1Map[1] (hashed true/false) is not a number`); process.exit(1); }
			switch (coseSign1Map[1]) {
				case 0: coseSign1Map[1] = { "hashed": false }; var verifyDataHex = payloadCborHash; break; //payload was not hashed
				case 1: coseSign1Map[1] = { "hashed": true }; var verifyDataHex = getHash(payloadCborHash); break; //payload was hashed, so we also hash our comparising message
				default:  console.error(`Error: coseSign1Map[1] (hashed true/false) is not 0 or 1`); process.exit(1); break; //only 0 and 1 are supported,otherwise throw an error
			}

			//convert the coseKeyMap and coseSign1Map into cbor-hex strings to pass it to the verification function and also to output it in json-extended format
			var coseKeyHex = cbor.encode(coseKeyMap).toString('hex')
			var coseSign1Hex = cbor.encode(coseSign1Map).toString('hex')

			//verify the cip8 signature
			try {
				var ret = verifyCIP8('verify-cip88',
							[ '--cip8',
							  '--cose-sign1', coseSign1Hex, 				//pass it as cbor encoded hex string
							  '--cose-key', coseKeyHex,					//pass it as cbor encoded hex string
							  '--nohashcheck', '--json-extended',				//we already did the hash check above
							  '--data-hex', verifyDataHex ] ); 				//we provide the self generated data for checking and not the included one
			} catch (error) { console.error(`Error: CIP8 verification error ${error.msg}`); process.exit(1); }

			var json_ret = JSON.parse(ret.content);

			//compose the content for the output
			if ( args['json'] === true ) { //generate content in json format
				var content = `{ "result": "${json_ret['result']}" }`;
			} else if ( args['json-extended'] === true ) { //generate content in json format with additional fields

				//generate the calidus-id in hex and bech format for the json-extended output
				var calidusIdHex = `a1${getHash(calidusPubKeyHex, 28)}`; //hash the calidus publicKey with blake2b_224 (28bytes digest length) and add the prebyte a1=CalidusPoolKey
				var calidusIdBech = bech32.encode("calidus", bech32.toWords(Buffer.from(calidusIdHex, "hex")), 128); //encode in bech32 with a raised limit to 128 words because of the longer hash (56bytes)

				//generate the bech pool-id for the json-extended output
				var poolIdBech = bech32.encode("pool", bech32.toWords(Buffer.from(scopePoolIdHex, "hex")), 128); //encode in bech32 with a raised limit to 128 words because of the longer hash (56bytes)

				var content = `{ "workMode": "${workMode}", "result": "${ret.verified}", "poolIdHex": "${scopePoolIdHex}", "poolIdBech": "${poolIdBech}", `;
				content += `"calidusPublicKey": "${calidusPubKeyHex}", "calidusIdHex": "${calidusIdHex}", "calidusIdBech": "${calidusIdBech}", "publicKey": "${pubKeyHex}", `;
				content += `"nonce": ${payloadMap.get(4)}, "payloadCbor": "${payloadCborHex}", "payloadHash": "${payloadCborHash}", "isHashed": "${json_ret['isHashed']}", "verifyDataHex": "${verifyDataHex}", `;
				content += `"coseSign1Hex": "${coseSign1Hex}", "coseKeyHex": "${coseKeyHex}", "coseSignature": "${json_ret['signature']}" }`;

			} else { //generate content in text format
				var content = `${json_ret['result']}`;
			}

			//output the content to the console or to a file
			var out_file = args['out-file'];
		        //if there is no --out-file parameter specified or the parameter alone (true) then output to the console
			if ( typeof out_file === 'undefined' || out_file == '' ) { console.log(content);} //Output to console
			else { //else try to write the content out to the given file
				try {
					fs.writeFileSync(out_file,content, 'utf8')
					// file written successfully
				} catch (error) { console.error(`${error}`); process.exit(1); }
			}

			break;


		default:
		        //if workMode is not found, exit with and errormessage and showUsage
			console.error(`Error: Unsupported mode '${workMode}'`);
			showUsage();

	} //switch

}

//main();
main().catch( (err) => {process.exit(1);} );

//process.exit(0); //we're finished, exit with errorcode 0 (all good)
