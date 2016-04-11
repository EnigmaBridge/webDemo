"use strict";
/**
 * Convenience shortcuts.
 */
var h = sjcl.codec.hex;
var utf = sjcl.codec.utf8String;

/**
 * Global shortcuts to fields.
 */
var htmlBody;
var templateField;
var chkPassword;
var chkHotp;
var fldRegPassword;
var fldRegUsername;
var btnRegRandomUsername;
var btnCreateUser;
var divQrCode;
var fldRegUserCtx;
var fldRegUserCtxCrc;

// Basic HOTP record.
var hotpRecord = function(){};
hotpRecord.prototype = {
	userId: undefined,
	secret: undefined,
	counter: undefined,
	ctx: undefined
};

var userNameMap = {};

/**
 * Global section with variables.
 */
var names = ['test', 'john', 'alice', 'bob', 'eve', 'mallory', 'rick', 'bruce', 'mathew', 'alan', 'linus', 'petr', 'dan'];
var templateHotpDigits = 6;
var requestConfig = {
	remoteEndpoint: 'site1.enigmabridge.com',
	remotePort: 11180,
	requestMethod: "POST",
	requestScheme: 'https',
	requestTimeout: 10000,
	debuggingLog: true,
	apiKey: "TEST_API",
	aesKey: '1234567890123456789012345678901234567890123456789012345678901234',
	macKey: '2224262820223456789012345678901234567890123456789012345678901234'
};

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
 * Switches main loading overlay.
 * @param started if true overlay is displayed. Hidden otherwise.
 */
function bodyProgress(started){
	if (started){
		htmlBody.addClass("loading");
	} else {
		htmlBody.removeClass("loading");
	}
}

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
		options.hotp.digits = templateHotpDigits;
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

	log("Template generated: " + response);
}

function btnGenNameClick(){
	var name = names[Math.floor(Math.random()*names.length)];
	fldRegUsername.val(name);
}

function btnCreateUserClick(){
	try {
		var options = getTemplateSettings(fldRegPassword.val());
		var reqSettings = $.extend(requestConfig, {
			apiKeyLow4Bytes: 0x8855,
			userObjectId: 0x8855,
			callRequestType: 'AUTH_NEWUSERCTX'
		});

		// Create name if not created.
		var usrName = fldRegUsername.val();
		if (usrName === undefined || usrName.length == 0) {
			btnGenNameClick();
		}

		log("Create Auth context configuration: " + JSON.stringify(options));
		var request = new eb.comm.hotp.newHotpUserRequest(options);
		request.configure(reqSettings);

		// Callbacks settings.
		request.done(function (response, requestObj, data) {
			log("DONE! " + response.toString());
			createUserFinished(response);

		}).fail(function (failType, data) {
			log("fail! type=" + failType + ", response=" + (data && data.response ? data.response.toString() : 'undefined') + "\n data=" + JSON.stringify(data));
			createUserFailed(failType, data);

		}).always(function (request, data) {
			log("Request finished");
			bodyProgress(false);
		});

		// Build the request so we can display request in the form.
		request.build();

		// Do the call.
		fldRegUserCtx.val('...');
		successBg(fldRegUserCtx);
		bodyProgress(true);

		request.doRequest();
	} catch(e){
		log("Exception: " + e);
		scrollToTarget('#step1');
		throw e;
	}
}

function createUserFinished(response){
	var record = new hotpRecord();

	// Response status code handling.
	var responseStatus = response.hotpStatus;
	if ((responseStatus === undefined || responseStatus == 0x0) && response.statusCode != eb.comm.status.SW_STAT_OK){
		responseStatus = response.statusCode;
	}

	var status = '';
	if (responseStatus == eb.comm.status.SW_STAT_OK){
		status += 'Success.';
	} else {
		status += 'Failed.';
	}

	fldRegUserCtx.val(status);
	successBg(fldRegUserCtx, response.hotpStatus == eb.comm.status.SW_STAT_OK);

	// Fail.
	if (responseStatus != eb.comm.status.SW_STAT_OK){
		fldRegUserCtxCrc.val('');
		return;
	}

	// Success, happy path.
	record.userId = sjcl.codec.hex.fromBits(eb.comm.hotp.userIdToBits(response.hotpUserId));
	record.ctx = sjcl.codec.hex.fromBits(response.hotpUserCtx);

	fldRegUserCtx.val(record.ctx);
	fldRegUserCtxCrc.val(eb.misc.genChecksumValue(record.ctx, 4));

	if (response.hotpKey){
		record.secret = sjcl.codec.hex.fromBits(response.hotpKey);
		var qrLink2 = eb.comm.hotp.hotpGetQrLink(response.hotpKey, {
			label: sjcl.codec.hex.fromBits(response.hotpUserId),
			web: "demo.enigmabridge.com",
			issuer: "EnigmaBridge",
			ctr:0,
			digits: templateHotpDigits,
			stripPadding: true
		});

		log("QR link: " + qrLink2);
		divQrCode.html("");
		divQrCode.qrcode(qrLink2);
	}

	// Store this record to the local database.
	userNameMap[fldRegUsername.val()] = record;
}

function createUserFailed(failType, data){
	fldRegUserCtx.val("");
	fldRegUserCtxCrc.val("");
	if (failType == eb.comm.status.PDATA_FAIL_CONNECTION){
		fldRegUserCtx.val("Connection error");
	} else {
		fldRegUserCtx.val("Request failed");
	}

	successBg(fldRegUserCtx, false);
}

$(function()
{
	htmlBody = $("body");
	templateField = $('#systemtemplate');
	chkPassword = $('#ch-method-pwd');
	chkHotp = $('#ch-method-hotp');
	fldRegPassword = $('#add_password');
	fldRegUsername = $('#add_username');
	btnRegRandomUsername = $('#btnGenRandom');
	btnCreateUser = $('#btnCreateUser');
	divQrCode = $('#qrCode');
	fldRegUserCtx = $('#userctxnew');
	fldRegUserCtxCrc = $('#userctxnew_crc');

	$("#btnSystemInit").click(function(){
		btnGenerateTemplate();
	});

	btnRegRandomUsername.click(function(){
		btnGenNameClick();
	});

	btnCreateUser.click(function(){
		btnCreateUserClick();
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