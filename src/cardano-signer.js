//define name and version
const appname = "cardano-signer"
const version = "1.15.1"

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

//set the options for the command-line arguments. needed so that arguments like data-hex="001122" are not parsed as numbers
const parse_options = {
	string: ['secret-key', 'public-key', 'signature', 'address', 'rewards-address', 'payment-address', 'vote-public-key', 'data', 'data-hex', 'data-file', 'out-file', 'out-cbor', 'out-skey', 'out-vkey', 'cose-sign1', 'cose-key', 'mnemonics', 'path', 'testnet-magic'],
	boolean: ['help', 'version', 'usage', 'json', 'json-extended', 'cip8', 'cip30', 'cip36', 'deregister', 'jcli', 'bech', 'hashed', 'nopayload', 'vkey-extended'], //all booleans are set to false per default
	//adding some aliases so users can also use variants of the original parameters. for example using --signing-key instead of --secret-key
	alias: { 'deregister': 'deregistration', 'cip36': 'cip-36', 'cip8': 'cip-8', 'cip30': 'cip-30', 'secret-key': 'signing-key', 'public-key': 'verification-key', 'rewards-address': 'reward-address', 'data': 'data-text', 'jcli' : 'bech', 'mnemonic': 'mnemonics', 'vkey-extended': 'with-chain-code' },
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
const regExpPath = /^[0-9]+H\/[0-9]+H\/[0-9]+H(\/[0-9]+H?){0,2}$/;  //path: first three elements must always be hardened, max. 5 elements

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

	case 'verify':
	        console.log(``)
	        console.log(`${Bright}${Underscore}Verify a hex/text-string or a binary-file via signature + publicKey:${Reset}`)
	        console.log(``)
	        console.log(`   Syntax: ${Bright}${appname} ${FgGreen}verify${Reset}`);
		console.log(`   Params: ${FgGreen}--data-hex${Reset} "<hex>" | ${FgGreen}--data${Reset} "<text>" | ${FgGreen}--data-file${Reset} "<path_to_file>"${Reset}`);
		console.log(`							${Dim}data/payload/file to verify in hex-, text- or binary-file-format${Reset}`);
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
		console.log(`           [${FgGreen}--hashed${Reset}]						${Dim}optional flag to hash the payload given via the 'data' parameters${Reset}`);
		console.log(`           [${FgGreen}--json${Reset} |${FgGreen} --json-extended${Reset}]				${Dim}optional flag to generate output in json/json-extended format${Reset}`);
		console.log(`           [${FgGreen}--out-file${Reset} "<path_to_file>"]			${Dim}path to an output file, default: standard-output${Reset}`);
	        console.log(`   Output: ${FgCyan}"true/false" (exitcode 0/1)${Reset} or ${FgCyan}JSON-Format${Reset}`)
	        console.log(``)
		break;

	case 'keygen':
	case 'keygen-cip36':
	        console.log(``)
	        console.log(`${Bright}${Underscore}Generate Cardano ed25519/ed25519-extended keys:${Reset}`)
	        console.log(``)
	        console.log(`   Syntax: ${Bright}${appname} ${FgGreen}keygen${Reset}`);
		console.log(`   Params: [${FgGreen}--path${Reset} "<derivationpath>"]				${Dim}optional derivation path in the format like "1852H/1815H/0H/0/0" or "1852'/1815'/0'/0/0"${Reset}`);
		console.log(`								${Dim}or predefined names: --path payment, --path stake, --path cip36, --path drep, --path cc-cold, --path cc-hot${Reset}`);
		console.log(`           [${FgGreen}--mnemonics${Reset} "word1 word2 ... word24"]		${Dim}optional mnemonic words to derive the key from (separate via space)${Reset}`);
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

	default:
		showUsage('sign',false);
		showUsage('sign-cip8',false)
		showUsage('sign-cip36',false)
		showUsage('verify',false)
		showUsage('verify-cip8',false)
		showUsage('keygen',false)
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


function readKey2hex(key,type) { //reads a standard-cardano-skey/vkey-file-json, a direct hex entry or a bech-string  // returns a hexstring of the key

	//inputs:
	//	key -> string that points to a file or direct data
	//	type -> string 'secret' or 'public'

	//returns:
	//	secretkey 32 or 64 bytes long (type = secret)
	//	publickey 32 bytes long (type = public)

	var key_hex = "";

	switch (type) {

		case "secret": //convert a secret key into a hex string, always returns the full privat-key-hex (extended or non-extended)

			// try to use the parameter as a filename for a cardano skey json with a cborHex entry
			try {
				const key_json = JSON.parse(fs.readFileSync(key,'utf8')); //parse the given key as a json file
				const is_signing_key = key_json.type.toLowerCase().includes('signing') //boolean if the json contains the keyword 'signing' in the type field
				if ( ! is_signing_key ) { console.error(`Error: The file '${key}' is not a signing/secret key json`); process.exit(1); }
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

			// try to use the parameter as a filename for a cardano vkey json with a cborHex entry
			try {
				const key_json = JSON.parse(fs.readFileSync(key,'utf8')); //parse the given key as a json file
				const is_verification_key = key_json.type.toLowerCase().includes('verification') //boolean if the json contains the keyword 'verification' in the type field
				if ( ! is_verification_key ) { console.error(`Error: The file '${key}' is not a verification/public key json`); process.exit(1); }
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
	let addr_hex, addr_type, addr_network;
	let addr_matchPubKey = false;

	// first check, if the given address is an empty string, exit with an error
	if ( trimString(addr) == '' ) { console.error(`Error: The address value is empty`); process.exit(1); }

	// try to use the parameter as a filename for a bech encoded string in it (typical .addr files)
	try {  // outer try is needed to check if the file is present in first place
		const content = trimString(fs.readFileSync(addr,'utf8')); //read the content of the given addr from a file
		try { // inner try to check if the content is a bech address
			addr_hex = CardanoWasm.Address.from_bech32(content).to_hex();
		} catch (error) { console.error(`Error: The address in file '${addr}' is not a valid bech address`); process.exit(1); }
	} catch (error) {}

	// try to use the parameter as a bech encoded string
	if ( ! addr_hex ) {
		try {
			addr_hex = CardanoWasm.Address.from_bech32(addr).to_hex();
		} catch (error) {}
	}

	// try to use the parameter as a direct hex string
	if ( ! addr_hex ) {
		addr_hex = trimString(addr.toLowerCase());
		//check that the given key is a hex string
		if ( ! regExpHex.test(addr_hex) ) { console.error(`Error: Provided address '${addr}' is not a valid hex string, bech encoded address, or the file is missing`); process.exit(1); }
	}

	// we have a valid address in the addr_hex variable

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

	// get the address network informatino
	switch (addr_hex.substring(1,2)) {
		case '0': addr_network = 'testnet'; break;
		case '1': addr_network = 'mainnet'; break;
		default: addr_network = 'unknown';
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

			//generate the public key from the secret key for external verification
			var pubKey = Buffer.from(prvKey.to_public().as_bytes()).toString('hex')

			//get signing address (stake or paymentaddress in bech format)
			var address = args['address'];
		        if ( typeof address === 'undefined' || address === true ) { console.error(`Error: Missing signing address parameter`); showUsage(workMode); }

			//read the address from a file or direct hex/bech. also do a match check against the public key
		        sign_addr = readAddr2hex(address, pubKey);

			//check that the given address belongs to the current network
			if ( ( sign_addr.network == 'mainnet' ) && !(typeof args['testnet-magic'] === 'undefined') ) { // check for mainnet address
				console.error(`Error: The mainnet ${sign_addr.type} address '${sign_addr.addr}' does not match your current '--testnet-magic xxx' setting.`); process.exit(1); }
			else if ( ( sign_addr.network == 'testnet' ) && (typeof args['testnet-magic'] === 'undefined') ) { // check for testnet address
				console.error(`Error: The testnet ${sign_addr.type} address '${sign_addr.addr}' does not match your current setting. Use '--testnet-magic xxx' for testnets.`); process.exit(1); }

                        //check that the given address belongs to the pubKey
                        if ( ! sign_addr.matchPubKey ) { //exit with an error if the address does not contain the pubKey hash
                                console.error(`Error: The ${sign_addr.type} address '${sign_addr.addr}' does not belong to the provided secret key.`); process.exit(1);
			}

			//get payload-hex to sign -> store it in payload_data_hex
			var payload_data_hex = args['data-hex'];
		        if ( typeof payload_data_hex === 'undefined' || payload_data_hex === true ) {

				//no data-hex parameter present, lets try the data parameter
				var payload_data = args['data'];
			        if ( typeof payload_data === 'undefined' || payload_data === true ) {

					//no data parameter present, lets try the data-file parameter
					var payload_data_file = args['data-file'];
				        if ( typeof payload_data_file === 'undefined' || payload_data_file === true ) {console.error(`Error: Missing data / data-hex / data-file to sign`); showUsage(workMode);}

					//data-file present lets read the file and store it hex encoded in payload_data_hex
					try {
						payload_data_hex = fs.readFileSync(payload_data_file,null).toString('hex'); //reads the file as binary
					} catch (error) { console.error(`Error: Can't read data-file '${payload_data_file}'`); process.exit(1); }

				} else {
				//data parameter present, lets convert it to hex and store it in the payload_data_hex variable
				payload_data_hex = Buffer.from(payload_data).toString('hex');
				}

			} else {
				//data-hex is present, lets trim it, convert it to lowercase
			        payload_data_hex = trimString(payload_data_hex.toLowerCase());
				//check that the given data is a hex string, skip the test if payload_data_hex is empty. a nullstring is ok.
				if ( payload_data_hex != '' && ! regExpHex.test(payload_data_hex) ) { console.error(`Error: Data to sign is not a valid hex string`); process.exit(1); }
			}

			var payload_data_hex_orig = payload_data_hex //copy the payload_data_hex for later json output (in case its hashed)

			//generate the protectedHeader as an inner cbor (serialized Map)
			// alg (1) - must be set to EdDSA (-8)
			// kid (4) - Optional, if present must be set to the same value as in the COSE_Key specified below. It is recommended to be set to the same value as in the "address" header.
			// "address" - must be set to the raw binary bytes of the address as per the binary spec, without the CBOR binary wrapper tag
			var protectedHeader_cbor_hex = Buffer.from(cbor.encode(new Map().set(1,-8).set('address',Buffer.from(sign_addr.hex,'hex')))).toString('hex')

			//hash the payload if its set via the flag --hashed. this is used if the payload gets too big, or if f.e. a hw-wallet cannot display the payload (non ascii)
			var isHashed = args['hashed'];
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
			} catch (error) { console.error(`Error: ${error}`); process.exit(1); }

			//generate the signed message structure
			//COSE_Sign1_structure = [
			//  bstr,               ; protected header
			//  { * label => any }, ; unprotected header
			//  bstr / nil,         ; message(payload) to sign
			//  bstr                ; signature
			//  ]
			if ( args['nopayload'] ) { //the payload can be excluded from the COSE_Sign1 signature if the payload is known by the involved entities
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
			if ( args['json'] === true ) { //generate content in json format
				var content = `{ "COSE_Sign1_hex": "${COSE_Sign1_cbor_hex}", "COSE_Key_hex": "${COSE_Key_cbor_hex}" }`;
			} else if ( args['json-extended'] === true ) { //generate content in json format with additional fields

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

			//output the signature data and the public key to the console or to a file
			var out_file = args['out-file'];
		        //if there is no --out-file parameter specified or the parameter alone (true) then output to the console
			if ( typeof out_file === 'undefined' || out_file === true ) { console.log(content); }
			else { //else try to write the content out to the given file
				try {
				fs.writeFileSync(out_file,content, 'utf8')
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
			const registrationMap = delegationMap.set(61285,new Map().set(1,Buffer.from(signature,'hex')))

			//convert it to a cbor hex string
			const registrationCBOR = Buffer.from(cbor.encode(registrationMap)).toString('hex');

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

			//get optional payload_data_hex to use in case there is no payload present in the COSE_Sign1 signature
			var data_hex = args['data-hex'];
		        if ( typeof data_hex === 'string' ) { // a nullstring is also ok
				//data-hex is present, lets trim it, convert it to lowercase
			        var payload_data_hex = trimString(data_hex.toLowerCase());
				//check that the given data is a hex string, skip the test if its empty. a nullstring is ok
				if ( payload_data_hex != '' && ! regExpHex.test(payload_data_hex) ) { console.error(`Error: Data is not a valid hex string`); process.exit(1); }
			}


			if ( ! payload_data_hex ) { //no payload_data_hex present, lets try the data-file parameter
				var payload_data_file = args['data-file'];
			        if ( typeof payload_data_file === 'string' && payload_data_file != '' ) {
					//data-file present lets read the file and store it hex encoded in payload_data_hex
						try {
							var payload_data_hex = fs.readFileSync(payload_data_file,null).toString('hex'); //reads the file as binary
						} catch (error) { console.error(`Error: Can't read data-file '${payload_data_file}'`); process.exit(1); }
				}
			}

			if ( ! payload_data_hex ) { //no payload_data_hex present, lets try the data (data-hex) parameter
				var payload_data = args['data'];
			        if ( typeof payload_data === 'string' ) { // a nullstring is also ok
					//data parameter present, lets convert it to hex and store it in the payload_data_hex variable
					var payload_data_hex = Buffer.from(payload_data).toString('hex');
				}
			}

			//there might be a payload_data_hex preset now, or it is 'undefined' if not provided via the optional data parameters


			//get the COSE_Key to verify
			var COSE_Key_cbor_hex = args['cose-key'];
		        if ( typeof COSE_Key_cbor_hex === 'undefined' || COSE_Key_cbor_hex === true ) { console.error(`Error: Missing COSE_Key parameter --cose-key`); showUsage(workMode); }
			COSE_Key_cbor_hex = trimString(COSE_Key_cbor_hex.toLowerCase());

			//check that COSE_Key_cbor_hex is a valid hex string before passing it on to the cbor decoding
			if ( ! regExpHex.test(COSE_Key_cbor_hex) ) { console.error(`Error: COSE_Key is not a valid hex string`); process.exit(1); }

			//cbor decode the COSE_Key_cbor_hex into the COSE_Key_structure
			try {
				var COSE_Key_structure = cbor.decode(COSE_Key_cbor_hex)
			} catch (error) { console.error(`Error: Can't cbor decode the given COSE_Key signature (${error})`); process.exit(1); }

			//do a sanity check on the decoded COSE_Key_structure
			if ( ! COSE_Key_structure instanceof Map || COSE_Key_structure.size < 4 ) { console.error(`Error: COSE_Key is not valid. It must be a map with at least 4 entries: kty,alg,crv,x.`); process.exit(1); }
			else if ( COSE_Key_structure.get(1) != 1 ) { console.error(`Error: COSE_Key map label '1' (kty) is not '1' (OKP)`); process.exit(1); }
			else if ( COSE_Key_structure.get(3) != -8 ) { console.error(`Error: COSE_Key map label '3' (alg) is not '-8' (EdDSA)`); process.exit(1); }
			else if ( COSE_Key_structure.get(-1) != 6 ) { console.error(`Error: COSE_Key map label '-1' (crv) is not '6' (Ed25519)`); process.exit(1); }
			else if ( ! COSE_Key_structure.has(-2) ) { console.error(`Error: COSE_Key map label '-2' (public key) is missing`); process.exit(1); }

			//get the publickey
			var pubKey_buffer =  COSE_Key_structure.get(-2);
			if ( ! Buffer.isBuffer(pubKey_buffer) ) { console.error(`Error: PublicKey entry in the COSE_Key is not a bytearray`); process.exit(1); }
			var pubKey = pubKey_buffer.toString('hex')

			//load the publickey
			try {
			var publicKey = CardanoWasm.PublicKey.from_bytes(Buffer.from(pubKey,'hex'));
			} catch (error) { console.error(`Error: ${error}`); process.exit(1); }

			//get the COSE_Sign1 signature to verify
			var COSE_Sign1_cbor_hex = args['cose-sign1'];
		        if ( typeof COSE_Sign1_cbor_hex === 'undefined' || COSE_Sign1_cbor_hex === true ) { console.error(`Error: Missing COSE_Sign1 signature parameter --cose-sign1`); showUsage(workMode); }
			COSE_Sign1_cbor_hex = trimString(COSE_Sign1_cbor_hex.toLowerCase());

			//check that COSE_Sign1_cbor_hex is a valid hex string before passing it on to the cbor decoding
			if ( ! regExpHex.test(COSE_Sign1_cbor_hex) ) { console.error(`Error: COSE_Sign1 is not a valid hex string`); process.exit(1); }

			//cbor decode the COSE_Sign1_cbor_hex into the COSE_Sign1_structure
			try {
				var COSE_Sign1_structure = cbor.decode(COSE_Sign1_cbor_hex)
			} catch (error) { console.error(`Error: Can't cbor decode the given COSE_Sign1 signature (${error})`); process.exit(1); }

			//do a sanity check on the decoded COSE_Sign1_structure
			if ( COSE_Sign1_structure instanceof Array == false || COSE_Sign1_structure.length != 4 ) { console.error(`Error: COSE_Sign1 is not a valid signature. It must be an array with 4 entries.`); process.exit(1); }

			//extract the content: protectedHeader, unprotectedHeader, payload, signature
			//
			// 1) protectedHeader

				var protectedHeader_buffer = COSE_Sign1_structure[0];
				if ( ! Buffer.isBuffer(protectedHeader_buffer) ) { console.error(`Error: Protected header is not a bytearray (serialized) cbor`); process.exit(1); }
				//cbor decode the protectedHeader_cbor_hex into protectedHeader
				try {
					var protectedHeader = cbor.decode(protectedHeader_buffer)
				} catch (error) { console.error(`Error: Can't cbor decode the protected header (${error})`); process.exit(1); }

				//extract the content and do a check on the map entries
				if ( ! protectedHeader.has(1) ) { console.error(`Error: Protected header map label '1' is missing`); process.exit(1); }
				else if ( protectedHeader.get(1) != -8 ) { console.error(`Error: Protected header map label '1' (alg) is not '-8' (EdDSA)`); process.exit(1); }
				else if ( ! protectedHeader.has('address') ) { console.error(`Error: Protected header map label 'address' is missing`); process.exit(1); }
				var sign_addr_buffer = protectedHeader.get('address');
				if ( ! Buffer.isBuffer(sign_addr_buffer) ) { console.error(`Error: Protected header map label 'address' invalid`); process.exit(1); }

				//if there is an optional address parameter present, use it instead of the one from the COSE_Sign1 signature
	                        var address = args['address'];
	                        if ( typeof address === 'string' ) { //do the check if the parameter is provided
					//read the address from a file or direct hex/bech
				        sign_addr = readAddr2hex(address, pubKey);
		                        //check that the given address belongs to the pubKey
		                        if ( ! sign_addr.matchPubKey ) { //exit with an error if the address does not contain the pubKey hash
		                                console.error(`Error: The given ${sign_addr.type} address '${sign_addr.addr}' does not belong to the public key in the COSE_Key.`); process.exit(1);
					}

				} else {
					//read the sign_addr from the protectedHeader
				        sign_addr = readAddr2hex(sign_addr_buffer.toString('hex'), pubKey);
		                        //check that the address belongs to the pubKey
		                        if ( ! sign_addr.matchPubKey ) { //exit with an error if the address does not contain the pubKey hash
		                                console.error(`Error: The ${sign_addr.type} address '${sign_addr.addr}' in the COSE_Sign1 does not belong to the public key in the COSE_Key.`); process.exit(1);
					}
				}

			// 2) unprotectedHeader -> get the value for the isHashed boolean

				var unprotectedHeader = COSE_Sign1_structure[1];
				// cbor decode generates an object out of a map if there is only one entry. we want always a map, because there could be more entries
				if ( unprotectedHeader instanceof Map == false && typeof unprotectedHeader === 'object' ) { // so if it is not a map but an object, convert it
					var unprotectedHeader = new Map(Object.entries(unprotectedHeader));
				}

				if ( unprotectedHeader instanceof Map == false ) { // if its not a map now, throw an error
					console.error(`Error: Unprotected header is not a map`); process.exit(1);
				}

				if ( ! unprotectedHeader.has('hashed') ) { console.error(`Error: Unprotected header label 'hashed' is missing`); process.exit(1); }
				var isHashed = unprotectedHeader.get('hashed');
				if ( typeof isHashed !== 'boolean' ) { console.error(`Error: Unprotected header label 'hashed' is not a boolean`); process.exit(1); }

				//if there is already a payload_data_hex present via the optional data parameters, hash it if needed to match the settings in the COSE_Sign1 signature
				if ( payload_data_hex && isHashed ) { payload_data_hex = getHash(payload_data_hex, 28); } //hash the payload with blake2b_224 (28bytes digest length) }

			// 3) payload

				//if there is no payload_data_hex present via the optional data parameters, use the one in the COSE_Sign1 signature
				if ( typeof payload_data_hex === 'undefined' ) {
					var payload_data_buffer = COSE_Sign1_structure[2];
					if ( Buffer.isBuffer(payload_data_buffer) ) { // payload present, load it into payload_data_hex
						var payload_data_hex = payload_data_buffer.toString('hex');
					} else if ( payload_data_buffer == null ) { // payload is missing, and there is also no payload provided via the optional data parameters
						console.error(`Error: There is no payload present in the COSE_Sign1 signature, please provide a payload via the data / data-hex / data-file parameters`); process.exit(1);
					}
				}

			// 4) signature

				var signature_buffer = COSE_Sign1_structure[3];
				if ( ! Buffer.isBuffer(signature_buffer) ) { console.error(`Error: Signature is not a bytearray`); process.exit(1); }
				var signature_hex = signature_buffer.toString('hex')

				//load the Ed25519Signature
				try {
				var ed25519signature = CardanoWasm.Ed25519Signature.from_hex(signature_hex);
				} catch (error) { console.error(`Error: ${error}`); process.exit(1); }


			//generate the protectedHeader with the current values (the address within it might have been overwritten by a given one)
			// alg (1) - must be set to EdDSA (-8)
			// kid (4) - Optional, if present must be set to the same value as in the COSE_Key specified below. It is recommended to be set to the same value as in the "address" header.
			// "address" - must be set to the raw binary bytes of the address as per the binary spec, without the CBOR binary wrapper tag
			var protectedHeader_cbor_hex = Buffer.from(cbor.encode(new Map().set(1,-8).set('address',Buffer.from(sign_addr.hex,'hex')))).toString('hex')

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


			//compose the content for the output: signature data + public key
			if ( args['json'] === true ) { //generate content in json format
				var content = `{ "result": "${verified}" }`;
			} else if ( args['json-extended'] === true ) { //generate content in json format with additional fields
				var content = `{ "workMode": "${workMode}", "result": "${verified}", "addressHex": "${sign_addr.hex}", "addressType": "${sign_addr.type}", "addressNetwork": "${sign_addr.network}", `;
				if ( payload_data_hex.length <= 2000000 ) { content += `"payloadDataHex": "${payload_data_hex}", `; } //only include the payload_data_hex if it is less than 2M of chars
				content += `"isHashed": "${isHashed}",`;
				if ( Sig_structure_cbor_hex.length <= 2000000 ) { content += `"verifyDataHex": "${Sig_structure_cbor_hex}", `; } //only include the Sig_structure_cbor_hex if it is less than 2M of chars
				content += `"signature": "${signature_hex}",`;
				content += `"publicKey": "${pubKey}" }`
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


                case "keygen":  //KEY GENERATION
                case "keygen-cip36":

			//setup
			var XpubKeyHex = '', XpubKeyBech = '', vote_purpose = -1, drepIdHex = '', drepIdBech = '', ccColdIdHex = '', ccColdIdBech = '', ccHotIdHex = '', ccHotIdBech = '', prvKeyBech = '', pubKeyBech = '';

			//get the path parameter, if ok set the derivation_path variable
			var derivation_path = args['path'];
		        if ( typeof derivation_path === 'string' && derivation_path != '' ) { //ok, a path was provided let check
				derivation_path = trimString(derivation_path.toUpperCase());

				//predefined derivation paths via name
				switch (derivation_path) {
					case 'PAYMENT': derivation_path = '1852H/1815H/0H/0/0'; break;
					case 'STAKE': derivation_path = '1852H/1815H/0H/2/0'; break;
					case 'CIP36': derivation_path = '1694H/1815H/0H/0/0'; break;
					case 'DREP': derivation_path = '1852H/1815H/0H/3/0'; break;
					case 'CC-COLD': derivation_path = '1852H/1815H/0H/4/0'; break;
					case 'CC-HOT': derivation_path = '1852H/1815H/0H/5/0'; break;
				}

				if ( derivation_path.indexOf(`'`) > -1 ) { derivation_path = derivation_path.replace(/'/g,'H'); } //replace the ' char with a H char
				if ( ! regExpPath.test(derivation_path) ) { console.error(`Error: The provided derivation --path '${derivation_path}' does not match the right format! Example: 1852H/1815H/0H/0/0`); process.exit(1); }
			} else {
				var derivation_path = ''; //no path provided, set the derivation_path variable to be empty
			}


			//load or overwrite derivation path if CIP36 vote keys are selected
			if ( args['cip36'] === true ) { var derivation_path = '1694H/1815H/0H/0/0' }


			//get mnemonics parameter, if ok set the mnemonics variable
			var mnemonics = args['mnemonics'];
		        if ( typeof mnemonics === 'string' && mnemonics != '' ) { //ok, a path was provided let check
				mnemonics = trimMnemonic(mnemonics.toLowerCase());
				var mnemonicsWordCount = wordCount(mnemonics);
				if ( mnemonicsWordCount < 12 || mnemonicsWordCount > 24 ) { console.error(`Error: Please provide between 12 and 24 words for the --mnemonics.`); process.exit(1); }

				//calculate the entropy of the given mnemonic
				try {
					var entropy = Buffer.from(bip39.mnemonicToEntropy(mnemonics),'hex')
				} catch (error) { console.error(`Error: The provided mnemonics are not valid, please check the correct spelling. '${error}'`); process.exit(1); }

				//set the derivation path to the default if not already set before
				if ( derivation_path == '' ) { derivation_path = '1852H/1815H/0H/0/0'; }

			} else { //no mnemonics provided, generate a random entropy and get the mnemonics from it
				var entropy = crypto.randomBytes(32); //new random entropy
				var mnemonics = bip39.entropyToMnemonic(entropy); //get the mnemonics from the entropy
			}

			//if there is no derivation_path set, than a simple normal ed25519 key (not derived) is requested
			if ( derivation_path == '' ) { //generate a simple ed25519 keypair

				try {
				        var rootKey = CardanoWasm.PrivateKey.generate_ed25519(); //generate a new ed25519 key
					var prvKeyHex = Buffer.from(rootKey.as_bytes()).toString('hex'); //private-secret key in hex format
					var pubKeyHex = Buffer.from(rootKey.to_public().as_bytes()).toString('hex'); //public key in hex format
				} catch (error) { console.error(`Error: Could not generate a new ed25519 keypair. '${error}'`); process.exit(1); }
				var entropy = '', mnemonics = '';

			} else { //derivation path is present

				try {
					var rootKey = CardanoWasm.Bip32PrivateKey.from_bip39_entropy(entropy,''); //generate a ed25519e key from the provided entropy(mnemonics)
				} catch (error) { console.error(`Error: Could not generate the rootKey from the entropy/mnemonic. '${error}'`); process.exit(1); }

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

					var skeyContent = `{ "type": "CIP36VoteExtendedSigningKey_ed25519", "description": "${vote_purpose_description} Vote Signing Key", "cborHex": "${prvKeyCbor}" }`;
					if ( args['vkey-extended'] === true ) {
						var vkeyContent = `{ "type": "CIP36VoteExtendedVerificationKey_ed25519", "description": "${vote_purpose_description} Vote Verification Key", "cborHex": "${pubKeyCbor}" }`;
					} else {
						var vkeyContent = `{ "type": "CIP36VoteVerificationKey_ed25519", "description": "${vote_purpose_description} Vote Verification Key", "cborHex": "${pubKeyCbor}" }`;
					}
					//generate the keys also in bech format
					var prvKeyBech = bech32.encode("cvote_sk", bech32.toWords(Buffer.from(prvKeyHex, "hex")), 256); //encode in bech32 with a raised limit to 256 words because of the extralong privatekey (128bytes)
					var pubKeyBech = bech32.encode("cvote_vk", bech32.toWords(Buffer.from(pubKeyHex, "hex")), 128); //encode in bech32 with a raised limit to 128 words because of the longer publickey (64bytes)

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


						default: //looks like a payment key
							var skeyContent = `{ "type": "PaymentExtendedSigningKeyShelley_ed25519_bip32", "description": "Payment Signing Key", "cborHex": "${prvKeyCbor}" }`;

							if ( args['vkey-extended'] === true ) {
								var vkeyContent = `{ "type": "PaymentExtendedVerificationKeyShelley_ed25519_bip32", "description": "Payment Verification Key", "cborHex": "${pubKeyCbor}" }`;
							} else {
								var vkeyContent = `{ "type": "PaymentVerificationKeyShelley_ed25519", "description": "Payment Verification Key", "cborHex": "${pubKeyCbor}" }`;
							}


					} //switch (derivation_path.split('/')[3])
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
				if ( derivation_path != '' ) { content += `, "path": "${derivation_path}"`; }
				if ( vote_purpose > -1 ) { content += `, "votePurpose": "${vote_purpose_description} (${vote_purpose})"`; }
				if ( mnemonics != '' ) { content += `, "mnemonics": "${mnemonics}"`; }
				content += `, "secretKey": "${prvKeyHex}", "publicKey": "${pubKeyHex}"`;
				if ( XpubKeyHex != '' ) { content += `, "XpubKeyHex": "${XpubKeyHex}", "XpubKeyBech": "${XpubKeyBech}"`; }
				if ( drepIdHex != '' ) { content += `, "drepIdHex": "${drepIdHex}", "drepIdBech": "${drepIdBech}"`; }
				else if ( ccColdIdHex != '' ) { content += `, "ccColdIdHex": "${ccColdIdHex}", "ccColdIdBech": "${ccColdIdBech}"`; }
				else if ( ccHotIdHex != '' ) { content += `, "ccHotIdHex": "${ccHotIdHex}", "ccHotIdBech": "${ccHotIdBech}"`; }
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

		default:
		        //if workMode is not found, exit with and errormessage and showUsage
			console.error(`Error: Unsupported mode '${workMode}'`);
			showUsage();

	} //switch

}

main();

process.exit(0); //we're finished, exit with errorcode 0 (all good)
