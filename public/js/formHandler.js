"use strict";
String.prototype.isEmpty = function() {
	return (this.length === 0 || !this.trim());
};

function set_request(msg){
	$("#request").html(msg);
}

function display_message(msg) {
	$("#status").html(msg);
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
	var status = $("#status");
	var oldMsg = status.html();
	var newMsg = formatDate(new Date()) + " - " + msg;

	status.html(oldMsg.isEmpty() ? newMsg : (oldMsg + "<br/>\n" + newMsg));
}

function log(msg){
	console.log(msg);
	append_message(msg);
}

function requestSimple(dataInp, doPadding){
	var h = sjcl.codec.hex;
	var apiKey = 'API_TEST';
	var aesKey = 'e134567890123456789012345678901234567890123456789012345678901234';
	var macKey = 'e224262820223456789012345678901234567890123456789012345678901234';
	var keyId = 0xee01;
	var endpoint = 'dragonfly.smarthsm.net';
	var method = 'POST';
	var scheme = 'https';

	var plainData = h.toBits("");
	var requestData = h.toBits(dataInp || ""); //sjcl.codec.utf8String.toBits(data);

	if (doPadding){
		var pad = eb.padding.pkcs7;
		requestData = pad.pad(requestData);
		append_message("Padded req: " + h.fromBits(requestData));
	}

	// Flush old messages.
	display_message("");
	set_request("");

	var logger = function(msg) {
		append_message(msg);
	};

	var request = new eb.comm.request();
	request.aesKey = aesKey;
	request.macKey = macKey;
	request.apiKey = apiKey;
	request.userObjectId = keyId;

	// Advanced settings.
	request.remoteEndpoint = endpoint;
	request.remotePort = 11180;
	request.requestMethod = method;
	request.requestScheme = scheme;
	request.requestTimeout = 7000;
	request.callFunction = "ProcessData";
	request.callRequestType = "PLAINAES";

	// Logging settings.
	request.debuggingLog = true;
	request.logger = logger;

	// Callbacks settings.
	request.done(function(response, requestObj, jqXHR) {
		console.log("DONE! " + h.fromBits(response.protectedData));
		$('#data_encrypted').val(h.fromBits(response.protectedData));

	}).fail(function(failType, jqXHR, textStatus, errorThrown, requestObj){
		console.log("fail! type=" + failType);

	}).always(function(request){
		console.log("it is over...");
	});

	// Build the request so we can display request in the form.
	request.build(plainData, requestData);

	// Uncomment for full request view.
	//set_request(sprintf("%s<br/>\n%s<br/>\n%s<br/>\n",
	//	request.getApiUrl(),
	//	JSON.stringify(request.getApiRequestData()),
	//	JSON.stringify(request.getSocketRequest())));

	set_request(JSON.stringify(request.getSocketRequest()));

	// Do the call.
	request.call();
}

$(function()
{
	var successMsg = "Your message has been sent."; // Message shown on success.
	var failMsg = "Sorry it seems that our server is not responding, Sorry for the inconvenience!"; // Message shown on fail.
	
	$("input,textarea").jqBootstrapValidation(
    {
     	preventSubmit: true,
     	submitSuccess: function($form, event)
	 	{
			event.preventDefault(); // prevent default submit behaviour
			requestSimple($('#data_encrypt').val(), true);

			//var processorFile = "./bin/"+$form.attr('id')+".php";
			//var formData = {};
            //
			//$form.find("input, textarea").each(function(e) // Loop over form objects build data object
			//{
			//	formData[$(this).attr('id')] = $(this).val();
			//});
            //
			//$.ajax({
		     //   url: processorFile,
		    	//type: "POST",
		    	//data: formData,
		    	//cache: false,
		    	//success: function() // Success
		 	//	{
			//		$form.append("<div id='form-alert'><div class='alert alert-success'><button type='button' class='close' data-dismiss='alert' aria-hidden='true'>&times;</button><strong>"+successMsg+"</strong></div></div>");
		 	//   	},
			//   	error: function() // Fail
			//   	{
			//		$form.append("<div id='form-alert'><div class='alert alert-danger'><button type='button' class='close' data-dismiss='alert' aria-hidden='true'>&times;</button><strong>"+failMsg+"</strong></div></div>");
			//   	},
			//	complete: function() // Clear
			//	{
			//		$form.trigger("reset");
			//	},
		   	//});
         },
         filter: function() // Handle hidden form elements
		 {
			 return $(this).is(":visible");
         },
	 });
});