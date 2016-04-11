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
var logElem;

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

var fldLoginUsername;
var fldLoginPassword;
var btnLoginPasswordWrong;
var btnLoginPasswordOK;
var fldLoginResult;
var fldLoginCtx;
var fldLoginCtxCrc;
var btnLogin;
var radLoginPassword;
var radLoginHotp;

var fldChangeUsername;
var fldChangeCurrentPassword;
var fldChangeNewPassword;
var btnChangeGenNewPassword;
var btnChangePassword;
var fldChangeStatus;
var fldChangeCtx;
var fldChangeCtxCrc;

var radResetPassword;
var radResetHotp;
var fldResetUsername;
var fldResetPassword;
var btnResetRandomPassword;
var btnResetPassword;
var fldResetStatus;
var fldResetCtx;
var fldResetCtxCrc;
var fldResetQr;

// Basic HOTP record.
var hotpRecord = function(){};
hotpRecord.prototype = {
	userId: undefined,
	secret: undefined,
	counter: undefined,
	ctx: undefined,

	// Demo fields
	password: undefined,
	lastSuccessHotp: undefined
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
	append_message(msg);
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
	var newMsg = formatDate(new Date()) + " - " + msg;
	logElem.val((logElem.val() + "\n" + newMsg).trim());
}

function isChecked(elem){
	return elem.is(':checked');
}

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
	var authPasswd = isChecked(chkPassword);
	var authHotp = isChecked(chkHotp);
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
	var authPasswd = isChecked(chkPassword);
	var authHotp = isChecked(chkHotp);

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
		var request = new eb.comm.hotp.newHotpUserRequest({hotp:options});
		request.configure(reqSettings);
		request.logger = append_message;

		// Callbacks settings.
		request.done(function (response, requestObj, data) {
			log("DONE! " + response.toString());
			createUserFinished(response);

		}).fail(function (failType, data) {
			log("fail! type=" + failType + ", response=" + (data && data.response ? data.response.toString() : 'undefined') + "\n data=" + JSON.stringify(data));
			createUserFailed(failType, data);

		}).always(function (request, data) {
			log("Create User Request finished");
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

function updateCrc(dstElem, srcData){
	dstElem.val(srcData !== undefined && srcData.length > 0 ? eb.misc.genChecksumValue(srcData, 4) : '');
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
	record.password = fldRegPassword.val();

	fldRegUserCtx.val(record.ctx);
	updateCrc(fldRegUserCtxCrc, record.ctx);

	if (response.hotpKey){
		record.counter = 1;
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

	fldLoginUsername.val(fldRegUsername.val());

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

function getUserRecord(uname){
	return userNameMap[uname];
}

function btnPasswordGenClick(correctOne){
	var uname = fldLoginUsername.val();
	var record = getUserRecord(uname);
	if (record === undefined){
		fldLoginResult.val("User was not found");
		successBg(fldLoginResult, false);
		return;
	}

	if (!correctOne){
		fldLoginPassword.val('InvalidPassword' + Math.floor(Math.random()*100));
		return;
	}

	var doHotp = isChecked(radLoginHotp);
	if (doHotp){
		var hotpSecretBits = sjcl.codec.hex.toBits(record.secret);
		var hotpCtr = record.counter;

		// Compute HOTP code.
		var hotpCode = eb.comm.hotp.hotpCompute(hotpSecretBits, hotpCtr, templateHotpDigits);
		var hotpCodeStr = sprintf("%0"+templateHotpDigits+"d", hotpCode);
		fldLoginPassword.val(hotpCodeStr);
		log(sprintf("HOTP code %s generated from ctr %d", hotpCodeStr, hotpCtr));

	} else {
		fldLoginPassword.val(record.password);
	}
}

function authFailed(data){
	fldLoginResult.val("Connection error");
	successBg(fldLoginResult, false);
}

function authFinished(record, response){
	var responseStatus = response.hotpStatus;
	if ((responseStatus === undefined || responseStatus == 0x0) && response.statusCode != eb.comm.status.SW_STAT_OK){
		responseStatus = response.statusCode;
	}

	var status = '';
	if (responseStatus == eb.comm.status.SW_STAT_OK){
		status += 'Authenticated successfully';
	} else if (responseStatus == eb.comm.status.SW_AUTH_TOO_MANY_FAILED_TRIES){
		status += 'Failed, too many attempts';
	} else if (responseStatus == eb.comm.status.SW_HOTP_TOO_MANY_FAILED_TRIES){
		status += 'Failed, too many HOTP attempts';
	} else if (responseStatus == eb.comm.status.SW_HOTP_WRONG_CODE && record.lastSuccessHotp == fldLoginPassword.val()) {
		status += 'Failed, HOTP can be used only once';
	} else if (responseStatus == eb.comm.status.SW_HOTP_WRONG_CODE) {
		status += 'Failed, invalid HOTP code';
	} else if (responseStatus == eb.comm.status.SW_WRONG_PASSWD){
		status += 'Failed, invalid password';
	} else if (responseStatus == eb.comm.status.SW_PASSWD_INVALID_LENGTH){
		status += 'Failed, invalid password length';
	} else if (responseStatus == eb.comm.status.SW_PASSWD_TOO_MANY_FAILED_TRIES){
		status += 'Failed, too many password attempts';
	} else if (responseStatus == eb.comm.status.SW_AUTHMETHOD_NOT_ALLOWED){
		status += 'Failed, authentication method not allowed';
	} else if (responseStatus == eb.comm.status.SW_INVALID_TLV_FORMAT){
		status += 'Failed, invalid auth request (empty password or HOTP?)';
	} else {
		status += 'Failed, error' + sprintf("0x%04X", responseStatus);
	}

	fldLoginResult.val(status);
	successBg(fldLoginResult, response.hotpStatus == eb.comm.status.SW_STAT_OK);

	var wasHotp = isChecked(radLoginHotp);
	if (response.hotpUserCtx){
		var newCtx = sjcl.codec.hex.fromBits(response.hotpUserCtx);
		record.ctx = newCtx;

		fldLoginCtx.val(newCtx);
		updateCrc(fldLoginCtxCrc, newCtx);
	}

	if (response.hotpStatus == eb.comm.status.SW_STAT_OK && wasHotp){
		record.lastSuccessHotp = fldLoginPassword.val();
		record.counter += 1;
		log("HOTP counter incremented to " + record.counter);
	}
}

function btnLoginClick(){
	// Get user record.
	var uname = fldLoginUsername.val();
	var record = getUserRecord(uname);
	if (!record){
		fldLoginResult.val("User was not found");
		successBg(fldLoginResult, false);
		return;
	}

	// Build request.
	fldLoginResult.val("...");
	successBg(fldLoginResult);

	// Auth Request
	var doHotp = isChecked(radLoginHotp);
	var reqSettings = $.extend(requestConfig, {
		apiKeyLow4Bytes: 	doHotp ? 0x5588 : 0x5599,
		userObjectId: 		doHotp ? 0x5588 : 0x5599,
		callRequestType: 	doHotp ? 'AUTH_HOTP' : 'AUTH_PASSWD'
	});

	var authCode = fldLoginPassword.val();
	var reqConfig = {hotp:{
		'userId': record.userId,
		'userCtx': record.ctx
	}};

	if (doHotp){
		reqConfig.hotp.hotpCode = authCode;
	} else {
		reqConfig.hotp.passwd = sjcl.hash.sha256.hash(authCode);
	}

	var request = new eb.comm.hotp.authHotpUserRequest(reqConfig);
	request.configure(reqSettings);
	request.logger = append_message;

	// Callbacks settings.
	request.done(function(response, requestObj, data) {
		log("DONE! " + response.toString());
		authFinished(record, response);

	}).fail(function(failType, data){
		log("fail! type=" + failType);
		if (failType == eb.comm.status.PDATA_FAIL_RESPONSE_FAILED){
			log("Fail msg: " + data.response.toString());
			authFinished(record, data.response);

		} else if (failType == eb.comm.status.PDATA_FAIL_CONNECTION){
			log("Connection error");
			authFailed(data);
		}

	}).always(function(request, data){
		log("Auth Request finished");
		bodyProgress(false);
	});

	// Build the request so we can display request in the form.
	request.build();

	// Do the call.
	fldLoginResult.val('...');
	successBg(fldLoginResult);
	bodyProgress(true);

	request.doRequest();
}

$(function()
{
	htmlBody = $("body");
	logElem = $("#log");
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
	fldLoginUsername = $('#login_username');
	fldLoginPassword = $('#login_password');
	btnLoginPasswordWrong = $('#btnLoginWrongPassword');
	btnLoginPasswordOK = $('#btnLoginCorrectPassword');
	fldLoginResult = $('#logon_result');
	fldLoginCtx = $('#userctxupdated');
	fldLoginCtxCrc = $('#userctxupdate_crc');
	btnLogin = $('#btnLogin');
	radLoginPassword = $('#rb-password');
	radLoginHotp = $('#rb-otp');

	fldChangeUsername = $('#username_change');
	fldChangeCurrentPassword = $('#currentpassword_change');
	fldChangeNewPassword = $('#newpassword_change');
	btnChangeGenNewPassword = $('#btnChangeGenNewPassword');
	btnChangePassword = $('#btnChangePassword');
	fldChangeStatus = $('#change_result');
	fldChangeCtx = $('#changectx');
	fldChangeCtxCrc = $('#changectx_crc');

	radResetPassword = $('#rs_reset_pwd');
	radResetHotp = $('#rs_reset_hotp');
	fldResetUsername = $('#reset_username');
	fldResetPassword = $('#input_1955');
	btnResetRandomPassword = $('#btnGenNewPassword');
	btnResetPassword = $('#btnResetPassword');
	fldResetStatus = $('#input_2646');
	fldResetCtx = $('#input_2679');
	fldResetCtxCrc = $('#input_1160');
	fldResetQr = $('#resetQr');

	$("#btnSystemInit").click(function(){
		btnGenerateTemplate();
	});

	btnRegRandomUsername.click(function(){
		btnGenNameClick();
	});

	btnCreateUser.click(function(){
		btnCreateUserClick();
	});

	btnLoginPasswordOK.click(function(){
		btnPasswordGenClick(true);
	});

	btnLoginPasswordWrong.click(function(){
		btnPasswordGenClick(false);
	});

	btnLogin.click(function(){
		btnLoginClick();
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