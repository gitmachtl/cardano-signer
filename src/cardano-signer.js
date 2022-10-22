//define name and version
const appname = "cardano-signer"
const version = "1.9.0"

//external dependencies
const CardanoWasm = require("@emurgo/cardano-serialization-lib-nodejs")
const cbor = require("cbor"); //decode and encode cbor
const bech32 = require("bech32").bech32;  //used, because the CardanoWasm does not support the decoding of general bech strings for the public/private key
const fs = require("fs"); //filesystem io
const blakejs = require('blakejs'); //alternative blake2 implementation
//const blake2 = require('blake2');

//set the options for the command-line arguments. needed so that arguments like data-hex="001122" are not parsed as numbers
const parse_options = {
	string: ['secret-key', 'public-key', 'signature', 'address', 'rewards-address', 'vote-public-key', 'data', 'data-hex', 'data-file', 'out-file', 'out-cbor'],
	number: ['nonce', 'vote-weight', 'vote-purpose'],
	boolean: ['json', 'json-extended', 'cip8', 'cip36', 'deregister'],
	//adding some aliases so users can also use variants of the original parameters. for example using --signing-key instead of --secret-key
	alias: { 'deregister': 'deregistration', 'cip36': 'cip-36', 'cip8': 'cip-8', 'secret-key': 'signing-key', 'public-key': 'verification-key', 'rewards-address': 'reward-address', 'data': 'data-text' }
};
const args = require('minimist')(process.argv.slice(2),parse_options);

//various constants
const regExpHex = /^[0-9a-fA-F]+$/;

//catch all exceptions that are not catched via try
process.on('uncaughtException', function (error) {
    console.error(`${error}`); process.exit(1);
});


function showUsage(){
//FontColors
Reset = "\x1b[0m"; Bright = "\x1b[1m"; Dim = "\x1b[2m"; Underscore = "\x1b[4m"; Blink = "\x1b[5m"; Reverse = "\x1b[7m"; Hidden = "\x1b[8m"
FgBlack = "\x1b[30m"; FgRed = "\x1b[31m"; FgGreen = "\x1b[32m"; FgYellow = "\x1b[33m"; FgBlue = "\x1b[34m"; FgMagenta = "\x1b[35m"; FgCyan = "\x1b[36m"; FgWhite = "\x1b[37m"

        console.log(``)
        console.log(`${Bright}${Underscore}Signing a hex/text-string or a binary-file:${Reset}`)
        console.log(``)
        console.log(`   Syntax: ${Bright}${appname} ${FgGreen}sign${Reset}`);
	console.log(`   Params: ${FgGreen}--data-hex${Reset} "<hex>" | ${FgGreen}--data${Reset} "<text>" | ${FgGreen}--data-file${Reset} "<path_to_file>"`);
	console.log(`								${Dim}data/payload/file to sign in hex-, text- or binary-file-format${Reset}`);
	console.log(`           ${FgGreen}--secret-key${Reset} "<path_to_file>|<hex>|<bech>"		${Dim}path to a signing-key-file or a direct signing hex/bech-key string${Reset}`);
	console.log(`           [${FgGreen}--json${Reset} |${FgGreen} --json-extended${Reset}]				${Dim}optional flag to generate output in json/json-extended format${Reset}`);
	console.log(`           [${FgGreen}--out-file${Reset} "<path_to_file>"]			${Dim}path to an output file, default: standard-output${Reset}`);
        console.log(`   Output: ${FgCyan}"signature_hex + publicKey_hex"${Reset} or ${FgCyan}JSON-Format${Reset}`);
        console.log(``)
        console.log(``)
        console.log(`${Bright}${Underscore}Signing a payload in CIP-8 mode:${Reset}`)
        console.log(``)
        console.log(`   Syntax: ${Bright}${appname} ${FgGreen}sign --cip8${Reset}`);
	console.log(`   Params: ${FgGreen}--data-hex${Reset} "<hex>" | ${FgGreen}--data${Reset} "<text>" | ${FgGreen}--data-file${Reset} "<path_to_file>"${Reset}`);
	console.log(`								${Dim}data/payload/file to sign in hex-, text- or binary-file-format${Reset}`);
	console.log(`           ${FgGreen}--secret-key${Reset} "<path_to_file>|<hex>|<bech>"		${Dim}path to a signing-key-file or a direct signing hex/bech-key string${Reset}`);
	console.log(`           ${FgGreen}--address${Reset} "<bech_address>" 				${Dim}signing address (bech format like 'stake1..., stake_test1...')${Reset}`);
	console.log(`           [${FgGreen}--testnet-magic [xxx]${Reset}]				${Dim}optional flag to switch the address check to testnet-addresses, default: mainnet${Reset}`);
	console.log(`           [${FgGreen}--json${Reset} |${FgGreen} --json-extended${Reset}]				${Dim}optional flag to generate output in json/json-extended format${Reset}`);
	console.log(`           [${FgGreen}--out-file${Reset} "<path_to_file>"]			${Dim}path to an output file, default: standard-output${Reset}`);
        console.log(`   Output: ${FgCyan}"signature_hex + publicKey_hex"${Reset} or ${FgCyan}JSON-Format${Reset}`);
        console.log(``)
        console.log(``)
        console.log(`${Bright}${Underscore}Signing a catalyst registration/delegation or deregistration in CIP-36 mode:${Reset}`)
        console.log(``)
        console.log(`   Syntax: ${Bright}${appname} ${FgGreen}sign --cip36${Reset}`);
	console.log(`   Params: [${FgGreen}--vote-public-key${Reset} "<path_to_file>|<hex>|<bech>"	${Dim}public-key-file(s) or public hex/bech-key string(s) to delegate the votingpower to (single or multiple)${Reset}`);
	console.log(`           ${FgGreen}--vote-weight${Reset} <unsigned_int>]			${Dim}relative weight of each delegated votingpower, default: 100% for a single delegation${Reset}`);
	console.log(`           ${FgGreen}--secret-key${Reset} "<path_to_file>|<hex>|<bech>"		${Dim}signing-key-file or a direct signing hex/bech-key string of the stake key (votingpower)${Reset}`);
	console.log(`           ${FgGreen}--rewards-address${Reset} "<bech_address>"			${Dim}rewards stake address (bech format like 'stake1..., stake_test1...')${Reset}`);
	console.log(`           [${FgGreen}--nonce${Reset} <unsigned_int>]				${Dim}optional nonce value, if not provided the mainnet-slotHeight calculated from current machine-time will be used${Reset}`);
	console.log(`           [${FgGreen}--vote-purpose${Reset} <unsigned_int>]			${Dim}optional parameter (unsigned int), default: 0 (catalyst)${Reset}`);
	console.log(`           [${FgGreen}--deregister${Reset}]					${Dim}optional flag to generate a deregistration (no --vote-public-key/--vote-weight/--rewards-address needed${Reset}`);
	console.log(`           [${FgGreen}--testnet-magic [xxx]${Reset}]				${Dim}optional flag to switch the address check to testnet-addresses, default: mainnet${Reset}`);
	console.log(`           [${FgGreen}--json${Reset} |${FgGreen} --json-extended${Reset}]				${Dim}optional flag to generate output in json/json-extended format, default: cborHex(text)${Reset}`);
	console.log(`           [${FgGreen}--out-file${Reset} "<path_to_file>"]			${Dim}path to an output file, default: standard-output${Reset}`);
	console.log(`           [${FgGreen}--out-cbor${Reset} "<path_to_file>"]			${Dim}path to write a binary metadata.cbor file to${Reset}`);
        console.log(`   Output: ${FgCyan}Registration-Metadata in JSON-, cborHex-, cborBinary-Format${Reset}`);
        console.log(``)
        console.log(``)
        console.log(`${Bright}${Underscore}Verifying a hex/text-string or a binary-file via signature + publicKey:${Reset}`)
        console.log(``)
        console.log(`   Syntax: ${Bright}${appname} ${FgGreen}verify${Reset}`);
	console.log(`   Params: ${FgGreen}--data-hex${Reset} "<hex>" | ${FgGreen}--data${Reset} "<text>" | ${FgGreen}--data-file${Reset} "<path_to_file>"${Reset}`);
	console.log(`								${Dim}data/payload/file to verify in hex-, text- or binary-file-format${Reset}`);
	console.log(`           ${FgGreen}--signature${Reset} "<hex>"					${Dim}signature in hexformat${Reset}`);
	console.log(`           ${FgGreen}--public-key${Reset} "<path_to_file>|<hex>|<bech>"		${Dim}path to a public-key-file or a direct public hex/bech-key string${Reset}`);
	console.log(`           [${FgGreen}--json${Reset} |${FgGreen} --json-extended${Reset}]				${Dim}optional flag to generate output in json/json-extended format${Reset}`);
	console.log(`           [${FgGreen}--out-file${Reset} "<path_to_file>"]			${Dim}path to an output file, default: standard-output${Reset}`);
        console.log(`   Output: ${FgCyan}"true/false" (exitcode 0/1)${Reset} or ${FgCyan}JSON-Format${Reset}`)
        console.log(``)
        console.log(``)
        console.log(`${Dim}${Underscore}Info:${Reset}`);
	console.log(`   ${Dim}https://github.com/gitmachtl (Cardano SPO Scripts \/\/ ATADA Stakepools Austria)${Reset}`)
        console.log(``)
        process.exit(1);
}


function trimString(s){
        s = s.replace(/(^\s*)|(\s*$)/gi,"");    //exclude start and end white-space
        s = s.replace(/\n /,"\n");              // exclude newline with a start spacing
        return s;
}


function readKey2hex(key,type) { //reads a standard-cardano-skey/vkey-file-json, a direct hex entry or a bech-string  // returns a hexstring of the key

	//inputs:
	//	key -> string that points to a file or direct data
	//	type -> string 'secret' or 'public'

	var key_hex = "";

	switch (type) {

		case "secret": //convert a secret key into a hex string, always returns the full privat-key-hex (extended or non-extended)

			// try to use the parameter as a filename for a cardano skey json with a cborHex entry
			try {
				const key_json = JSON.parse(fs.readFileSync(key,'utf8')); //parse the given key as a json file
				const is_singing_key = key_json.type.toLowerCase().includes('signing') //boolean if the json contains the keyword 'signing' in the type field
				if ( ! is_singing_key ) { console.error(`Error: The file '${key}' is not a signing/secret key json`); process.exit(1); }
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
//					const tmp_key = CardanoWasm.PrivateKey.from_bech32(content); //temporary key to check about bech32 format
//					key_hex = Buffer.from(tmp_key.as_bytes()).toString('hex');
				 } catch (error) { console.error(`Error: The content in file '${key}' is not a valid bech secret key`); process.exit(1); }
				return key_hex;
			} catch (error) {}

			// try to use the parameter as a bech encoded string
			try {
				key_hex = Buffer.from(bech32.fromWords(bech32.decode(key,1000).words)).toString('hex');
//				const tmp_key = CardanoWasm.PrivateKey.from_bech32(key); //temporary key to check about bech32 format
//				key_hex = Buffer.from(tmp_key.as_bytes()).toString('hex');
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
//					const tmp_key = CardanoWasm.PublicKey.from_bech32(content); //temporary key to check about bech32 format
//					key_hex = Buffer.from(tmp_key.as_bytes()).toString('hex');
				 } catch (error) { console.error(`Error: The content in file '${key}' is not a valid bech public key`); process.exit(1); }
				return key_hex.substring(0,64); //return a non-extended public key
			} catch (error) {}

			// try to use the parameter as a bech encoded string
			try {
				key_hex = Buffer.from(bech32.fromWords(bech32.decode(key,1000).words)).toString('hex');
//				const tmp_key = CardanoWasm.PublicKey.from_bech32(key); //temporary key to check about bech32 format
//				key_hex = Buffer.from(tmp_key.as_bytes()).toString('hex');
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

/*  //depricated function that uses the node-blake2 module, switched to blakejs
function getHash(content) { //hashes a given hex-string content with blake2b_256 (digestLength 32)
    const h = blake2.createHash("blake2b", { digestLength: 32 });
    h.update(Buffer.from(content, 'hex'));
    return h.digest("hex")
}
*/

function getHash(content) { //hashes a given hex-string content with blake2b_256 (digestLength 32, key = null)
    return blakejs.blake2bHex(Buffer.from(content,'hex'), null, 32)
}



// MAIN
//
// first parameter -> workMode: sign or verify
//
// workMode: sign (defaultmode without flags)
// --data / --data-hex -> textdata / hexdata that should be signed
//        --secret-key -> signing key in hex/bech/file format
//          --out-file -> signed data in hex format + public key in hex format
//
// workMode: sign --cip8 FLAG
// --data / --data-hex -> textdata / hexdata that should be signed
//        --secret-key -> signing key in hex/bech/file format
//           --address -> signing address
//          --out-file -> signed data in hex format + public key in hex format
//
// workMode: sign --cip36 FLAG
//   --vote-public-key -> public key in hex/bech/file format of the voting public key (one or multiple)
//       --vote-weight -> relative voting weight (one or multiple)
//        --secret-key -> signing key in hex/bech/file format
//   --rewards-address -> rewards stake address
//             --nonce -> nonce, typically the slotheight(tip) of the chain
//      --vote-purpose -> optional unsigned_int parameter, default: 0 (catalyst)
//        --deregister -> optional flag to produce an empty delegation array (deregistration)
//              --json -> optional flag to produce a json output
//     --json-extended -> optional flag to produce an extended json output
//          --out-file -> path to an output file
//          --out-cbor -> path to a binary metadata.cbor output file
//
// workMode: verify (defaultmode without flags)
// --data / --data-hex -> textdata / hexdata that should be verified
//         --signature -> signed data(signature) in hex format for verification
//        --public-key -> public key for verification in hex/bech/file format
//              output -> true (exitcode 0) or false (exitcode 1)
//

async function main() {

        //show help or usage if no parameter is provided
        if ( ! process.argv[2] || process.argv[2].toLowerCase().includes('help') || process.argv[2].toLowerCase().includes('usage') ) { console.log(`${appname} ${version}`); showUsage(); }

        //show version
        if ( process.argv[2].toLowerCase().includes('version') ) { console.log(`${appname} ${version}`); process.exit(0); }

        //first paramter - workMode: "sign or verify"
        var workMode = process.argv[2];
        if ( ! workMode ) { showUsage(); }
        workMode = trimString(workMode.toLowerCase());

	//CIP8-Flag-Check
        const cip8_flag = args['cip8'];
        if ( cip8_flag === true ) {workMode = workMode + '-cip8'}

	//CIP36-Flag-Check
        const cip36_flag = args['cip36'];
        if ( cip36_flag === true ) {
		workMode = workMode + '-cip36'
		//add deregister in CIP36 mode if the flag was set
		if ( args['deregister'] === true ) { workMode = workMode + "-deregister" }
	}

	//choose the workmode
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
				        if ( typeof sign_data_file === 'undefined' || sign_data_file === true ) {console.error(`Error: Missing data / data-hex / data-file to sign`); showUsage();}

					//data-file present lets read the file and store it hex encoded in sign_data_hex
					try {
						sign_data_hex = fs.readFileSync(sign_data_file,null).toString('hex'); //reads the file as binary
					} catch (error) { console.log(`Error: Can't read data-file '${sign_data_file}'`); process.exit(1); }

				} else {
				//data parameter present, lets convert it to hex and store it in the sign_data_hex variable
				sign_data_hex = Buffer.from(sign_data).toString('hex');
				}

			}
		        sign_data_hex = trimString(sign_data_hex.toLowerCase());

			//check that the given data is a hex string
			if ( ! regExpHex.test(sign_data_hex) ) { console.error(`Error: Data to sign is not a valid hex string`); showUsage(); }

			//get signing key -> store it in sign_key
			var key_file_hex = args['secret-key'];
		        if ( typeof key_file_hex === 'undefined' || key_file_hex === true ) { console.error(`Error: Missing secret key parameter`); showUsage(); }

			//read in the key from a file or direct hex
		        sign_key = readKey2hex(key_file_hex, 'secret');

			//load the private key (normal or extended)
			try {
			if ( sign_key.length <= 64 ) { var prvKey = CardanoWasm.PrivateKey.from_normal_bytes(Buffer.from(sign_key, "hex")); }
						else { var prvKey = CardanoWasm.PrivateKey.from_extended_bytes(Buffer.from(sign_key.substring(0,128), "hex")); } //use only the first 64 bytes (128 chars)
			} catch (error) { console.log(`Error: ${error}`); process.exit(1); }

			//generate the public key from the secret key for external verification
			var pubKey = Buffer.from(prvKey.to_public().as_bytes()).toString('hex')

			//sign the data
			try {
			var signedBytes = prvKey.sign(Buffer.from(sign_data_hex, 'hex')).to_bytes();
			var signature = Buffer.from(signedBytes).toString('hex');
			} catch (error) { console.error(`Error: ${error}`); process.exit(1); }

			//compose the content for the output: signature data + public key
			if ( args['json'] === true ) { //generate content in json format
				var content = `{ "signature": "${signature}", "publicKey": "${pubKey}" }`;
			} else if ( args['json-extended'] === true ) { //generate content in json format with additional fields
				var prvKeyHex = Buffer.from(prvKey.as_bytes()).toString('hex');
				var content = `{ "workMode": "${workMode}", `;
				if ( sign_data_hex.length <= 2000000 ) { content += `"signDataHex": "${sign_data_hex}", `; } //only include the sign_data_hex if it is less than 2M of chars
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


                case "sign-cip8":  //SIGN DATA IN CIP-8 MODE

			//get data-hex to sign -> store it in sign_data_hex
			var sign_data_hex = args['data-hex'];
		        if ( typeof sign_data_hex === 'undefined' || sign_data_hex === true ) {

				//no data-hex parameter present, lets try the data parameter
				var sign_data = args['data'];
			        if ( typeof sign_data === 'undefined' || sign_data === true ) {

					//no data parameter present, lets try the data-file parameter
					var sign_data_file = args['data-file'];
				        if ( typeof sign_data_file === 'undefined' || sign_data_file === true ) {console.error(`Error: Missing data / data-hex / data-file to sign`); showUsage();}

					//data-file present lets read the file and store it hex encoded in sign_data_hex
					try {
						sign_data_hex = fs.readFileSync(sign_data_file,null).toString('hex'); //reads the file as binary
					} catch (error) { console.log(`Error: Can't read data-file '${sign_data_file}'`); process.exit(1); }

				} else {
				//data parameter present, lets convert it to hex and store it in the sign_data_hex variable
				sign_data_hex = Buffer.from(sign_data).toString('hex');
				}

			}
		        sign_data_hex = trimString(sign_data_hex.toLowerCase());

			//check that the given data is a hex string
			if ( ! regExpHex.test(sign_data_hex) ) { console.error(`Error: Data to sign is not a valid hex string`); showUsage(); }

			var sign_data_hex_orig = sign_data_hex //copy the sign_data_hex for later json output

			//get signing address (stake or paymentaddress in bech format)
			var sign_addr = args['address'];
		        if ( typeof sign_addr === 'undefined' || sign_addr === true ) { console.error(`Error: Missing CIP-8 signing address (bech-format)`); showUsage(); }
		        sign_addr = trimString(sign_addr.toLowerCase());
			try {
				var sign_addr_hex = CardanoWasm.Address.from_bech32(sign_addr).to_hex();
			} catch (error) { console.error(`Error: The CIP-8 signing address '${sign_addr}' is not a valid bech address`); process.exit(1); }

			//check that the given address belongs to the current network
			//checks the second char (lower part of the first address byte) if its 1 for mainnet and 0 for testnets
			if ( (sign_addr_hex.substring(1,2) == "1") && !(typeof args['testnet-magic'] === 'undefined') ) { // check for mainnet address
				console.error(`Error: The mainnet address '${sign_addr}' does not match your current '--testnet-magic xxx' setting.`); process.exit(1); }
			else if ( (sign_addr_hex.substring(1,2) == "0") && (typeof args['testnet-magic'] === 'undefined') ) { // check for testnet address
				console.error(`Error: The testnet address '${sign_addr}' does not match your current setting. Use '--testnet-magic xxx' for testnets.`); process.exit(1); }

			//generate the Signature1 inner cbor (single signing key)
			const signature1_cbor = Buffer.from(cbor.encode(new Map().set(1,-8).set('address',Buffer.from(sign_addr_hex,'hex')))).toString('hex')

			//generate the data to sign cbor -> overwrites the current sign_data_hex variable at the end
			const sign_data_array = [ "Signature1", Buffer.from(signature1_cbor,'hex'),Buffer.from(''), Buffer.from(sign_data_hex,'hex') ]

			//overwrite the sign_data_hex with the cbor encoded sign_data_array
			sign_data_hex = cbor.encode(sign_data_array).toString('hex');

			//get signing key -> store it in sign_key
			var key_file_hex = args['secret-key'];
		        if ( typeof key_file_hex === 'undefined' || key_file_hex === true ) { console.error(`Error: Missing secret key parameter`); showUsage(); }

			//read in the key from a file or direct hex
		        sign_key = readKey2hex(key_file_hex, 'secret');

			//load the private key (normal or extended)
			try {
			if ( sign_key.length <= 64 ) { var prvKey = CardanoWasm.PrivateKey.from_normal_bytes(Buffer.from(sign_key, "hex")); }
						else { var prvKey = CardanoWasm.PrivateKey.from_extended_bytes(Buffer.from(sign_key.substring(0,128), "hex")); } //use only the first 64 bytes (128 chars)
			} catch (error) { console.log(`Error: ${error}`); process.exit(1); }

			//generate the public key from the secret key for external verification
			var pubKey = Buffer.from(prvKey.to_public().as_bytes()).toString('hex')

			//sign the data
			try {
			var signedBytes = prvKey.sign(Buffer.from(sign_data_hex, 'hex')).to_bytes();
			var signature = Buffer.from(signedBytes).toString('hex');
			} catch (error) { console.error(`Error: ${error}`); process.exit(1); }

			//compose the content for the output: signature data + public key
			if ( args['json'] === true ) { //generate content in json format
				var content = `{ "signature": "${signature}", "publicKey": "${pubKey}" }`;
			} else if ( args['json-extended'] === true ) { //generate content in json format with additional fields
				var prvKeyHex = Buffer.from(prvKey.as_bytes()).toString('hex');
				var content = `{ "workMode": "${workMode}", "addressHex": "${sign_addr_hex}", `;
				if ( sign_data_hex_orig.length <= 2000000 ) { content += `"inputDataHex": "${sign_data_hex_orig}", `; } //only include the sign_data_hex if it is less than 2M of chars
				if ( sign_data_hex.length <= 2000000 ) { content += `"signDataHex": "${sign_data_hex}", `; } //only include the sign_data_hex if it is less than 2M of chars
				content += `"signature": "${signature}", "secretKey": "${prvKeyHex}", "publicKey": "${pubKey}" }`;
			} else { //generate content in text format
				var content = signature + " " + pubKey;
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

			//get rewards stakeaddress in bech format
			var rewards_addr = args['rewards-address'];
		        if ( typeof rewards_addr === 'undefined' || rewards_addr === true ) { console.error(`Error: Missing rewards stake address (bech-format)`); process.exit(1); }
		        rewards_addr = trimString(rewards_addr.toLowerCase());
			if ( rewards_addr.substring(0,5) != 'stake' ) { console.error(`Error: The rewards stake address '${rewards_addr}' is not a stake address`); process.exit(1); }
			try {
				var rewards_addr_hex = CardanoWasm.Address.from_bech32(rewards_addr).to_hex();
			} catch (error) { console.error(`Error: The rewards stake address '${rewards_addr}' is not a valid bech address`); process.exit(1); }

			//check that the given address belongs to the current network
			//checks the second char (lower part of the first address byte) if its 1 for mainnet and 0 for testnets
			if ( (rewards_addr_hex.substring(1,2) == "1") && !(typeof args['testnet-magic'] === 'undefined') ) { // check for mainnet address
				console.error(`Error: The mainnet address '${rewards_addr}' does not match your current '--testnet-magic xxx' setting.`); process.exit(1); }
			else if ( (rewards_addr_hex.substring(1,2) == "0") && (typeof args['testnet-magic'] === 'undefined') ) { // check for testnet address
				console.error(`Error: The testnet address '${rewards_addr}' does not match your current setting. Use '--testnet-magic xxx' for testnets.`); process.exit(1); }

			//get signing key -> store it in sign_key
			var key_file_hex = args['secret-key'];
		        if ( typeof key_file_hex === 'undefined' || key_file_hex === true ) { console.error(`Error: Missing secret key parameter`); process.exit(1); }

			//read in the key from a file or direct hex
		        sign_key = readKey2hex(key_file_hex, 'secret');

			//load the private key (normal or extended)
			try {
			if ( sign_key.length <= 64 ) { var prvKey = CardanoWasm.PrivateKey.from_normal_bytes(Buffer.from(sign_key, "hex")); }
						else { var prvKey = CardanoWasm.PrivateKey.from_extended_bytes(Buffer.from(sign_key.substring(0,128), "hex")); } //use only the first 64 bytes (128 chars)
			} catch (error) { console.log(`Error: ${error}`); process.exit(1); }

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
		        if ( typeof vote_public_key === 'undefined' ) { console.error(`Error: Missing vote public key(s) parameter. For a deregistration please use the flag --deregister.`); process.exit(1); }

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
				  3: <stake_rewards_address>, // reward_address - byte array
				  4: <nonce> // nonce = slotHeight (tip)
				  5: <voting_purpose> // voting_purpose: 0 = Catalyst
			}
			*/
			const delegationMap = new Map().set(61284,new Map().set(1,vote_delegation_array).set(2,Buffer.from(pubKey,'hex')).set(3,Buffer.from(rewards_addr_hex,'hex')).set(4,nonce).set(5,vote_purpose));

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
				var content = `{ "61284": { "1": [ ${delegations} ], "2": "0x${pubKey}", "3": "0x${rewards_addr_hex}", "4": ${nonce}, "5": ${vote_purpose} }, "61285": { "1": "0x${signature}" } }`;
			} else if ( args['json-extended'] === true ) { //generate content in json format with additional fields
				var prvKeyHex = Buffer.from(prvKey.as_bytes()).toString('hex');
				var content = `{ "workMode": "${workMode}", "votePurpose": "${vote_purpose_description}", "totalVoteWeight": ${total_vote_weight}, "signDataHex": "${sign_data_hex}", "signature": "${signature}", "secretKey": "${prvKeyHex}", "publicKey": "${pubKey}", `;
				var delegations = [];
				for (let cnt = 0; cnt < all_vote_keys_array.length; cnt++) {
				delegations.push(`[ "0x${all_vote_keys_array[cnt]}", ${all_weights_array[cnt]} ]`)
				}
				content += `"output": { "cbor": "${registrationCBOR}", "json": { "61284": { "1": [ ${delegations} ], "2": "0x${pubKey}", "3": "0x${rewards_addr_hex}", "4": ${nonce}, "5": ${vote_purpose} }, "61285": { "1": "0x${signature}" } } } }`;
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
		        if ( typeof key_file_hex === 'undefined' || key_file_hex === true ) { console.error(`Error: Missing secret key parameter`); process.exit(1); }

			//read in the key from a file or direct hex
		        sign_key = readKey2hex(key_file_hex, 'secret');

			//load the private key (normal or extended)
			try {
			if ( sign_key.length <= 64 ) { var prvKey = CardanoWasm.PrivateKey.from_normal_bytes(Buffer.from(sign_key, "hex")); }
						else { var prvKey = CardanoWasm.PrivateKey.from_extended_bytes(Buffer.from(sign_key.substring(0,128), "hex")); } //use only the first 64 bytes (128 chars)
			} catch (error) { console.log(`Error: ${error}`); process.exit(1); }

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
				        if ( typeof verify_data_file === 'undefined' || verify_data_file === true ) {console.error(`Error: Missing data / data-hex / data-file to verify`); showUsage();}

					//data-file present lets read the file and store it hex encoded in verify_data_hex
					try {
						verify_data_hex = fs.readFileSync(verify_data_file,null).toString('hex'); //reads the file as binary
					} catch (error) { console.log(`Error: Can't read data-file '${verify_data_file}'`); process.exit(1); }

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
		        if ( typeof signature === 'undefined' || signature === true ) { console.error(`Error: Missing signature`); showUsage(); }
		        signature = trimString(signature.toLowerCase());

			//check that the given signature is a hex string
			if ( ! regExpHex.test(signature) ) { console.error(`Error: Signature is not a valid hex string`); process.exit(1); }

			//get public key -> store it in public_key
			var key_file_hex = args['public-key'];
		        if ( typeof key_file_hex === 'undefined' || key_file_hex === true ) { console.error(`Error: Missing public key parameter`); showUsage(); }

			//read in the key from a file or direct hex
		        public_key = readKey2hex(key_file_hex, 'public');

			//load the public key
			try {
			var publicKey = CardanoWasm.PublicKey.from_bytes(Buffer.from(public_key,'hex'));
			} catch (error) { console.error(`Error: ${error}`); process.exit(1); }

			//load the Ed25519Signature
			try {
			var ed25519signature = CardanoWasm.Ed25519Signature.from_hex(signature);
			} catch (error) { console.error(`Error: ${error}`); process.exit(1); }

			//do the verification
			const verified = publicKey.verify(Buffer.from(verify_data_hex,'hex'),ed25519signature);

			//compose the content for the output: signature data + public key
			if ( args['json'] === true ) { //generate content in json format
				var content = `{ "result": "${verified}" }`;
			} else if ( args['json-extended'] === true ) { //generate content in json format with additional fields
				var content = `{ "workMode": "${workMode}", "result": "${verified}", `;
				if ( verify_data_hex.length <= 2000000 ) { content += `"verifyDataHex": "${verify_data_hex}", `; } //only include the verify_data_hex if it is less than 2M of chars
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


		default:
		        //if workMode is not found, exit with and errormessage and showUsage
			console.error(`Error: Unsupported mode '${workMode}'`);
			showUsage();

	} //switch

}

main();

process.exit(0); //we're finished, exit with errorcode 0 (all good)


