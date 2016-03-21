"use strict";
/**
 * Convenience shortcuts.
 */
var h = sjcl.codec.hex;
var utf = sjcl.codec.utf8String;

/**
 * When particular process data operation is selected.
 * @param x
 */
function cryptoSelected(x){
	$('.group-radio-aes256').hide();
	$('.group-radio-rsa1024').hide();
	$('.group-radio-rsa2048').hide();
	$('.group-radio-'+x).show();
}

function rawToHexCoded(e, evt){
	var x = e.val();
	var ln = x.length;
	//console.log(x.length);
	//console.log(x[0]);
	// TODO: implement \bxy parser. \\ escaping.

	var y = jsesc(x, {
		'json': true
	});
	y = y.substring(1, y.length-1);
	console.log("jsesc: [" + y + "]");


	var i;
	for(i=0; i<ln; i++){

	}

	var bits = utf.toBits(x);
	return h.fromBits(bits);

	//return "";
}

function getByte(str, offset){
	var cByte = str[offset] + str[offset+1];
	var cBits = h.toBits(cByte);
	return sjcl.bitArray.extract(cBits,0,8);
}

function parseHexCodedData(x){
	var ln = x.length;

	// Process only even lengths.
	if ((ln & 1) == 1) {
		ln-=1;
	}

	var nonUtf8Chars = 0;
	var i, cByte, cBits, cStr, cNum;
	var out = [];

	// UTF8 encoding table
	//7 	U+0000	    U+007F	    1	0xxxxxxx
	//11	U+0080	    U+07FF	    2	110xxxxx	10xxxxxx
	//16	U+0800	    U+FFFF	    3	1110xxxx	10xxxxxx	10xxxxxx
	//21	U+10000	    U+1FFFFF	4	11110xxx	10xxxxxx	10xxxxxx	10xxxxxx
	//26	U+200000	U+3FFFFFF	5	111110xx	10xxxxxx	10xxxxxx	10xxxxxx	10xxxxxx
	//31	U+4000000	U+7FFFFFFF	6	1111110x	10xxxxxx	10xxxxxx	10xxxxxx	10xxxxxx	10xxxxxx
	for(i=0; i<ln; i+=2){
		cByte = (x[i] + x[i+1]).toLowerCase();
		cBits = h.toBits(cByte);
		cNum = sjcl.bitArray.extract(cBits,0,8);

		// 1byte char representation. ASCII.
		if ((cNum & 0x80) == 0){
			out.push({
				'b':1,
				'utf8':true,
				'hex':cByte,
				'enc':String.fromCharCode(cNum),
				'rep':String.fromCharCode(cNum)});
			continue;
		}

		// Look for utf8 character.
		var remBytes = (ln-i-2)/2;
		var valid = false;
		var j = 0;
		for(j=2; j<=6; j++){
			// Create first UTF8 byte mask signature, j = number of bytes character occupies.
			var signature = (Math.pow(2, j)-1)<<1;
			var byteLow = cNum >> (8-j-1);
			if (signature !== byteLow){
				continue;
			}

			// Signature matched, check if there is enough number of bytes in the buffer
			if (remBytes < (j-1)){
				break;
			}

			// Start building \uxxxx representation.
			var utfOut = h.toBits(sprintf("0000%x", cNum & ((1<<(8-j-1))-1) ) );
			var utfOutLen = sjcl.bitArray.bitLength(utfOut);
			if (utfOutLen > (8-j-1)){
				utfOut = sjcl.bitArray.bitSlice(utfOut, utfOutLen-(8-j-1));
			}

			// Check if each next byte has 10xxxxxx format.
			var k = 0;
			var byteValid = true;
			for(k=0; k<j-1; k++){
				var nByte = getByte(x, i+2+2*k);
				if ((nByte >>> 6) != 2){
					byteValid = false;
					break;
				}

				var cBitArray = h.toBits(sprintf("0000%x", nByte & ((1<<6)-1) ) );
				var cBitLen = sjcl.bitArray.bitLength(cBitArray);
				if (cBitLen >= 7){
					cBitArray = sjcl.bitArray.bitSlice(cBitArray, cBitLen-6);
				}

				utfOut = sjcl.bitArray.concat(utfOut, cBitArray);
			}

			// Successing were not in the 10xxxxxx format.
			if(!byteValid){
				break;
			}

			// utfOut needs to be left padded with zeros to be correctly interpreted.
			utfOutLen = sjcl.bitArray.bitLength(utfOut);
			if ((utfOutLen & 7) != 0){
				var toPadLen = 8-(utfOutLen & 7);
				utfOut = sjcl.bitArray.concat(sjcl.bitArray.bitSlice(h.toBits("00"),0,toPadLen), utfOut);
			}

			valid=true;
			out.push({
				'b':j,
				'utf8':true,
				'hex':cByte + x.substring(i+2, i+2+(j-1)*2),
				'enc':"\\u" + h.fromBits(utfOut),
				'rep':String.fromCharCode(parseInt(h.fromBits(utfOut), 16))
			});

			i+=2*(j-1);
			break;
		}

		if (valid){
			continue;
		}

		out.push({
			'b':1,
			'utf8':false,
			'hex':cByte,
			'enc':"\\x" + cByte,
			'rep':"\\x" + cByte});

		nonUtf8Chars+=1;
	}

	return {'nonUtf8Chars':nonUtf8Chars, 'parsed':out};
}

function printParsedHexData(parsed, options){
	var str="";
	var cur, i, len;
	for(i=0, len=parsed.parsed.length; i<len; i++){
		cur=parsed.parsed[i];
		str += cur.utf8 ? cur.rep : cur.enc;
	}

	return str;
}

function hexCodedToRaw(e, evt){
	var x = e.val();

	// Sanitize hex.
	var val = e.val();
	var oldval = val;
	val = val.replace(/[^a-fA-F0-9\s]+/g, "");
	if (oldval !== val) {
		e.val(val);
	}

	// Trip + whitespace removal
	x = x.trim();
	x = x.replace(/[\s\t\n]+/g, "");

	var parsed = parseHexCodedData(x);

	console.log(parsed);
	return printParsedHexData(parsed, {});
}

$(function()
{
	var successMsg = "Your message has been sent."; // Message shown on success.
	var failMsg = "Sorry it seems that our server is not responding, Sorry for the inconvenience!"; // Message shown on fail.

	// Basic form logic, hiding options when crypto is selected.
	cryptoSelected('aes256');
	$("#aes256").click(function(){ cryptoSelected('aes256'); });
	$("#rsa1024").click(function(){ cryptoSelected('rsa1024'); });
	$("#rsa2048").click(function(){ cryptoSelected('rsa2048'); });

	// Conversion from raw data to hexcoded and vice versa
	$("#dataraw").keyup(function(evt) {
		var src = $("#dataraw");
		var dst = $("#datahex");
		dst.val(rawToHexCoded(src, evt));
		//var bits = utf.toBits(src.val());
		//dst.val(h.fromBits(bits));
	});

	$("#datahex").keyup(function(evt) {
		var src = $("#datahex");
		var dst = $("#dataraw");
		dst.val(hexCodedToRaw(src, evt));
		//var bits = h.toBits(src.val());
		//dst.val(utf.fromBits(bits));
	});

	$("input,textarea").jqBootstrapValidation(
		{
			preventSubmit: true,
			submitSuccess: function($form, event)
			{
				event.preventDefault(); // prevent default submit behaviour



			},
			filter: function() // Handle hidden form elements
			{
				return $(this).is(":visible");
			},
		});
});