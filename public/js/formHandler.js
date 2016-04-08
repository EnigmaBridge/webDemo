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
	$("#dataraw").val("");
	$("#datahex").val("");

}

function successBg(x, success){
	if (success === undefined){
		x.removeClass('successBg');
		x.removeClass('failedBg');
	} else if (success){
		x.addClass('successBg');
		x.removeClass('failedBg');
	} else {
		x.removeClass('successBg');
		x.addClass('failedBg');
	}
}

function rawToHexCoded(e, evt) {
	var x = e.val();
	return eb.codec.utf8.toHex(x);
}

function hexCodedToRaw(e, evt) {
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

	return eb.codec.utf8.fromHex(x);
}

function set_request(msg){
	$("#request").val(msg);
}

function display_message(msg) {
	$("#log").val(msg);
}

function formatDate(date) {
	var hours = date.getHours();
	var minutes = date.getMinutes();
	var sec = date.getSeconds();
	var milli = date.getMilliseconds();
	var strTime = sprintf("%02d:%02d:%02d.%03d", hours, minutes, sec, milli);
	return date.getMonth()+1 + "/" + date.getDate() + "/" + date.getFullYear() + " " + strTime;
}

function append_message(msg) {
	var status = $("#log");
	var newMsg = formatDate(new Date()) + " - " + msg;
	status.val((status.val() + "\n" + newMsg).trim());
}

function log(msg){
	console.log(msg);
	append_message(msg);
}

function pkcs7pad(data){
	return sjcl.codec.hex.fromBits(eb.padding.pkcs7.pad(sjcl.codec.hex.toBits(data)));
}

function pkcs15pad(data, blockLen){
	return sjcl.codec.hex.fromBits(eb.padding.pkcs15.pad(sjcl.codec.hex.toBits(data), blockLen, 0));
}

function pkcs7unpad(data){
	return sjcl.codec.hex.fromBits(eb.padding.pkcs7.unpad(sjcl.codec.hex.toBits(data)));
}

function pkcs15unpad(data, blockLen){
	return sjcl.codec.hex.fromBits(eb.padding.pkcs15.unpad(sjcl.codec.hex.toBits(data), blockLen));
}

function connectionError(data){
	var statusElem = $('#responsetime');
	statusElem.val("Connection error\n" + data.requestObj.requestTime + ' ms');
	successBg(statusElem, false);
}

function finished(data){
	var statusElem = $('#responsetime');
	var responseStatus = data.response.statusCode;

	var status = sprintf("0x%04X", responseStatus);
	if (responseStatus == eb.comm.status.SW_STAT_OK){
		status += ' - OK';
	} else {
		status += ' - Failed';
	}

	status += "\n" + data.requestObj.requestTime + ' ms';

	statusElem.val(status);
	successBg(statusElem, responseStatus == eb.comm.status.SW_STAT_OK);
}

$(function()
{
	var successMsg = "Your message has been sent."; // Message shown on success.
	var failMsg = "Sorry it seems that our server is not responding, Sorry for the inconvenience!"; // Message shown on fail.

	// Basic form logic, hiding options when crypto is selected.
	$("#aes256").click(function(){
		cryptoSelected('aes256');
		$("#testvector").click();
	});

	$("#rsa1024").click(function(){
		cryptoSelected('rsa1024');
		$("#enigma1k").click();
	});

	$("#rsa2048").click(function(){
		cryptoSelected('rsa2048');
		$("#enigma2k").click();
	});

	// Shortcuts.
	var rdata = $("#dataraw");
	var odata = $("#datahex");

	// Conversion from raw data to hexcoded and vice versa
	rdata.keyup(function(evt) {
		var src = $("#dataraw");
		var dst = $("#datahex");
		dst.val(rawToHexCoded(src, evt));
	});

	odata.keyup(function(evt) {
		var src = $("#datahex");
		var dst = $("#dataraw");
		dst.val(hexCodedToRaw(src, evt));
	});

	// Data filling.
	// AES
	$("#allzeroes").click(function(){
		odata.val("00".repeat(8));
		odata.keyup();
	});
	$("#lowercasea").click(function(){
		rdata.val("a".repeat(8));
		rdata.keyup();
	});
	$("#testvector").click(function(){
		rdata.val("EnigmaTestVector");
		rdata.keyup();
	});

	// 1k RSA
	$("#testvector1k").click(function(){
		odata.val("1122334455667788112233445566778811223344556677881122334455667788112233445566778811223344556677881122334455667788112233445566778811223344556677881122334455667788112233445566778811223344556677881122334455667788112233445566778811223344556677881122334455667788");
		odata.keyup();
	});
	$("#one1k").click(function(){
		odata.val("01");
		odata.keyup();
	});
	$("#enigma1k").click(function(){
		odata.val(eb.codec.utf8.toHex("Enigma"));
		odata.keyup();
	});

	// 2k RSA
	$("#testvector2k").click(function(){
		odata.val("11223344556677881122334455667788112233445566778811223344556677881122334455667788112233445566778811223344556677881122334455667788112233445566778811223344556677881122334455667788112233445566778811223344556677881122334455667788112233445566778811223344556677881122334455667788112233445566778811223344556677881122334455667788112233445566778811223344556677881122334455667788112233445566778811223344556677881122334455667788112233445566778811223344556677881122334455667788112233445566778811223344556677881122334455667788");
		odata.keyup();
	});
	$("#one2k").click(function(){
		odata.val("01");
		odata.keyup();
	});
	$("#enigma2k").click(function(){
		odata.val(eb.codec.utf8.toHex("Enigma"));
		odata.keyup();
	});

	// CJS-1: select default values
	$("#aes256").click();

	// Form submission.
	$("input,textarea").jqBootstrapValidation(
		{
			preventSubmit: true,
			submitSuccess: function($form, event)
			{
				event.preventDefault(); // prevent default submit behaviour

				// Flush old messages.
				display_message("");
				set_request("");
				var logger = function(msg) {
					append_message(msg);
				};

				var body = $("body");
				var statusElem = $('#responsetime');
				$('#responsehex').val("");
				$('#responseraw').val("");
				statusElem.val("");

				// Request configuration generation.
				var endpoint = undefined;
				var scheme = undefined;
				if ($('#dragonfly').is(':checked')){
					endpoint = 'site1.enigmabridge.com';
					scheme = 'https';
				}
				if ($('#damselfly').is(':checked')) {
					endpoint = 'site2.enigmabridge.com';
					scheme = 'https';
				}

				var keyId = undefined;
				var pDataMethod = undefined;
				var encKey = undefined;
				var macKey = undefined;
				if ($('#aes256').is(':checked')){
					keyId = 0xEE01;
					pDataMethod = "PLAINAES";
					encKey = "e134567890123456789012345678901234567890123456789012345678901234";
					macKey = "e224262820223456789012345678901234567890123456789012345678901234";
				}
				if ($('#rsa1024').is(':checked')){
					keyId = 0x7654;
					pDataMethod = "RSA1024";
					encKey = "1234567890123456789012345678901234567890123456789012345678901234";
					macKey = "2224262820223456789012345678901234567890123456789012345678901234";
				}
				if ($('#rsa2048').is(':checked')){
					keyId = 0x9876;
					pDataMethod = "RSA2048";
					encKey = "1234567890123456789012345678901234567890123456789012345678901234";
					macKey = "2224262820223456789012345678901234567890123456789012345678901234";
				}

				var requestConfig = {
					remoteEndpoint: endpoint,
					remotePort: 11180,
					requestMethod: "POST",
					requestScheme: scheme,
					requestTimeout: 10000,
					debuggingLog: true,
					apiKey: "TEST_API",
					apiKeyLow4Bytes: keyId,
					userObjectId : keyId
				};

				var processDataConfig = {
					aesKey: encKey,
					macKey: macKey,
					callRequestType: pDataMethod
				};

				var inputData = odata.val();

				// PKCS 1.5 padding?
				if ($('#rsa1024').is(':checked') && ($('#one1k').is(':checked') || $('#enigma1k').is(':checked'))) {
					inputData = pkcs15pad(inputData, 1024/8);
					logger("Request was padded to 1024 bits (PKCS #1.5): " + inputData);
				}

				if ($('#rsa2048').is(':checked') && ($('#one2k').is(':checked') || $('#enigma2k').is(':checked'))) {
					inputData = pkcs15pad(inputData, 2048/8);
					logger("Request was padded to 2048 bits (PKCS #1.5): " + inputData);
				}

				// PKCS 7 padding
				if ($('#aes256').is(':checked')){
					inputData = pkcs7pad(inputData);
					logger("Request was padded to 128 bits block size (PKCS #7): " + inputData);
				}

				var plainData = h.toBits("");
				var requestData = h.toBits(inputData || "");

				// Build request
				var request = new eb.comm.processData();
				request.configure(requestConfig);
				request.configure(processDataConfig);

				// Logging settings.
				request.logger = logger;

				// Callbacks settings.
				request.done(function(response, requestObj, data) {
					$('#responsehex').val(h.fromBits(response.protectedData));
					$('#responseraw').val(JSON.stringify(requestObj.rawResponse));
					finished(data);

				}).fail(function(failType, data){
					console.log("fail! type=" + failType);
					$('#responsehex').val(" - ");
					$('#responseraw').val(JSON.stringify(data.response));

					if (failType == eb.comm.status.PDATA_FAIL_RESPONSE_FAILED){
						finished(data);

					} else if (failType == eb.comm.status.PDATA_FAIL_CONNECTION){
						log("Connection error");
						connectionError(data);
					}

				}).always(function(request, data){
					console.log("Processing finished");
					body.removeClass("loading");

				});

				// Build the request so we can display request in the form.
				request.build(plainData, requestData);
				set_request(sprintf("URL: %s\n%s",
					request.getApiUrl(),
					JSON.stringify(request.getApiRequestData())));

				// Status - loading
				statusElem.val('');
				successBg(statusElem);
				body.addClass("loading");

				// Do the call.
				request.doRequest();
			},
			filter: function() // Handle hidden form elements
			{
				return $(this).is(":visible");
			},
		});
});
