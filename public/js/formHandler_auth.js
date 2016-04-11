"use strict";
/**
 * Convenience shortcuts.
 */
var h = sjcl.codec.hex;
var utf = sjcl.codec.utf8String;

/*
 * Global shortcuts to fields.
 */
var templateField;
var chkPassword;
var chkHotp;
var fldRegPassword;

/**
 * Functions & handlers
 */
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

function log(msg){
	console.log(msg);
}

//function connectionError(data){
//	var statusElem = $('#responsetime');
//	statusElem.val("Connection error\n" + data.requestObj.requestTime + ' ms');
//	successBg(statusElem, false);
//}
//
//function finished(data){
//	var statusElem = $('#responsetime');
//	var responseStatus = data.response.statusCode;
//
//	/*var status = sprintf("0x%04X", responseStatus); */
//	var status = 'Response';
//	if (responseStatus == eb.comm.status.SW_STAT_OK){
//		status += ' - OK';
//	} else {
//		status += ' - Failed';
//	}
//
//	status += "\nin " + data.requestObj.requestTime + ' ms';
//
//	statusElem.val(status);
//	successBg(statusElem, responseStatus == eb.comm.status.SW_STAT_OK);
//}

/**
 * Returns basic template settings for Authentication initialization.
 * Uses form settings (auth/hotp)
 *
 * @returns template settings.
 */
function getTemplateSettings(passwd){
	var authPasswd = chkPassword.is(':checked');
	var authHotp = chkHotp.is(':checked');
	if (!authPasswd && !authHotp){
		throw new eb.exception.invalid("No auth method chosen");
	}

	var options = {methods: 0};
	if (authPasswd){
		options.methods |= eb.comm.hotp.USERAUTH_FLAG_PASSWD;
		options.passwd = {};

		var passwdHash = passwd !== undefined && passwd.length > 0 ? sjcl.hash.sha256.hash(passwd) : sjcl.hash.sha256.hash("");
		options.passwd.hash = sjcl.codec.hex.fromBits(passwdHash);
	}

	if (authHotp){
		options.methods |= eb.comm.hotp.USERAUTH_FLAG_HOTP;
		options.hotp = {};
		options.hotp.digits = 6;
	}

	return options;
}

/**
 * Called on template button click, generates template.
 */
function btnGenerateTemplate(){
	var authPasswd = chkPassword.is(':checked');
	var authHotp = chkHotp.is(':checked');

	successBg(templateField);
	if (!authPasswd && !authHotp){
		log("Cannot generate system parameters with no auth");
		templateField.val("Failed - Has to choose either password or HOTP authentication or both");
		successBg(templateField, false);
		return;
	}

	var options = getTemplateSettings();
	log(sprintf("Using passwords=%s, HOTP=%s for authentication system. Settings: %s", authPasswd, authHotp, JSON.stringify(options)));

	var template = eb.comm.hotp.getCtxTemplate(options);
	var contextPlaceholder = eb.comm.hotp.prepareUserContext(template);
	var response = sprintf("Success. Context length: %s B, CRC: %s, template: %s",
		sjcl.bitArray.bitLength(contextPlaceholder)/8,
		eb.misc.genChecksumValue(template, 4),
		sjcl.codec.hex.fromBits(template)
		);

	templateField.val(response);
	successBg(templateField, true);
	fldRegPassword.prop('disabled', !authPasswd);

	log("Template generated: %s", response);
}

$(function()
{
	templateField = $('#systemtemplate');
	chkPassword = $('#ch-method-pwd');
	chkHotp = $('#ch-method-hotp');
	fldRegPassword = $('#add_password');

	$("#btnSystemInit").click(function(){
		btnGenerateTemplate();
	});
	
	$("input,textarea").jqBootstrapValidation(
    {
     	preventSubmit: true,
     	submitSuccess: function($form, event)
	 	{
			event.preventDefault(); // prevent default submit behaviour
			
			// TODO: custom handling.
         },
         filter: function() // Handle hidden form elements
		 {
			 return $(this).is(":visible");
         },
	 });
});