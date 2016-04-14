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
var btnInitSystem;

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

// Basic Auth record for one user.
var authRecord = function(){};
authRecord.prototype = {
	userId: undefined,
	secret: undefined,
	counter: undefined,
	ctx: undefined,

	// Demo fields
	password: undefined,
	lastSuccessHotp: undefined,
	isPasswd: undefined,
	isHotp: undefined,
	username: undefined

};

// Global map storing username -> Auth record
var userNameMap = {};
var templateGenerated = false;
var doChangeAuthMethod = false;
var doAutogenerateTemplateSettingsOnChange = false;

/**
 * Global section with variables.
 */
var names = ['test', 'john', 'alice', 'bob', 'eve', 'mallory', 'rick', 'bruce', 'mathew', 'alan', 'linus', 'petr', 'dan'];
var templateHotpDigits = 6;
var requestConfig = {
	remoteEndpoint: 'site2.enigmabridge.com',
	remotePort: 11180,
	requestMethod: "POST",
	requestScheme: 'https',
	requestTimeout: 10000,
	debuggingLog: true,
	apiKey: "TEST_API",
	aesKey: '1234567890123456789012345678901234567890123456789012345678901234',
	macKey: '2224262820223456789012345678901234567890123456789012345678901234'
};

var svcSettings = {
	createUser: {
		uiod: 0x8855,
		requestType: 'AUTH_NEWUSERCTX'
	},

	auth: {
		hotp: {
			uiod: 0x5588,
			requestType: 'AUTH_HOTP'
		},
		password: {
			uiod: 0x5599,
			requestType: 'AUTH_PASSWD'
		}
	},

	updateUser: {
		uiod: 	0x55aa,
		requestType: 	'AUTH_UPDATEUSERCTX'
	}
};

// ---------------------------------------------------------------------------------------------------------------------
// Functions & handlers
// ---------------------------------------------------------------------------------------------------------------------

/**
 * Sets element its success class / background color. Used for status fields.
 * @param x
 * @param success if true, success is set, if false failed is set. If undefined, none is set (both classes removed), reset.
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

/**
 * Sets message to the status field together by setting its success class / background color.
 * @param x
 * @param msg
 * @param success
 */
function statusFieldSet(x, msg, success){
	x.val(msg);
	successBg(x, success);
}

/**
 * Simple logging method used in this script, passed to request objects for logging.
 * @param msg
 */
function log(msg){
	console.log(msg);
	append_message(msg);
}

/**
 * Helper method to format current date for the logging.
 * @param date
 * @returns {string}
 */
function formatDate(date) {
	var hours = date.getHours();
	var minutes = date.getMinutes();
	var sec = date.getSeconds();
	var milli = date.getMilliseconds();
	var strTime = sprintf("%02d:%02d:%02d.%03d", hours, minutes, sec, milli);
	return date.getMonth()+1 + "/" + date.getDate() + "/" + date.getFullYear() + " " + strTime;
}

/**
 * Appends message to log element
 * @param msg
 */
function append_message(msg) {
	var newMsg = formatDate(new Date()) + " - " + msg;
	logElem.val((logElem.val() + "\n" + newMsg).trim());
}

/**
 * Returns true if given radio button / checkbox is checked.
 * @param elem
 * @returns {*}
 */
function isChecked(elem){
	return elem.is(':checked');
}

/**
 * Sets given element as disabled.
 * @param elem
 * @param disabled
 */
function setDisabled(elem, disabled){
	elem.prop('disabled', disabled);
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

// ---------------------------------------------------------------------------------------------------------------------
// Create new user
// ---------------------------------------------------------------------------------------------------------------------

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
		statusFieldSet(templateField, "Failed - Has to choose either password or HOTP authentication or both", false);
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

	statusFieldSet(templateField, response, true);
	setDisabled(fldRegUsername, false);
	setDisabled(fldRegPassword, !authPasswd);
	templateGenerated = true;
	doAutogenerateTemplateSettingsOnChange = true;

	log("Template generated: " + response);
}

function btnGenNameClick(){
	if (!templateGenerated){
		scrollToTarget('#step1');
		return;
	}

	var name = names[Math.floor(Math.random()*names.length)];
	fldRegUsername.val(name);

	// Is password enabled?
	fldRegPassword.val(isChecked(chkPassword) ? name : '');
}

function btnCreateUserClick(){
	try {
		if (!templateGenerated){
			throw new eb.exception.invalid("You must generate template first");
		}

		var authPasswd = isChecked(chkPassword);
		var options = getTemplateSettings(fldRegPassword.val());
		var reqSettings = $.extend(requestConfig, {
			apiKeyLow4Bytes: 	svcSettings.createUser.uiod,
			userObjectId:		svcSettings.createUser.uiod,
			callRequestType: 	svcSettings.createUser.requestType
		});

		// Create name if not created.
		var usrName = fldRegUsername.val();
		if (usrName === undefined || usrName.length == 0) {
			btnGenNameClick();
		}

		// Set 'test' password if not set
		var usrPasswd = fldRegPassword.val();
		if (authPasswd && (usrPasswd === undefined || usrPasswd.length == 0)){
			fldRegPassword.val('test');
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
		statusFieldSet(fldRegUserCtx, '...');
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
	var record = new authRecord();

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
	var uname = fldRegUsername.val();
	record.userId = sjcl.codec.hex.fromBits(eb.comm.hotp.userIdToBits(response.hotpUserId));
	record.ctx = sjcl.codec.hex.fromBits(response.hotpUserCtx);
	record.password = fldRegPassword.val();
	record.isHotp = isChecked(chkHotp);
	record.isPasswd = isChecked(chkPassword);
	record.username = uname;

	fldRegUserCtx.val(record.ctx);
	updateCrc(fldRegUserCtxCrc, record.ctx);

	if (response.hotpKey){
		record.counter = 1;
		record.secret = sjcl.codec.hex.fromBits(response.hotpKey);
		var qrLink2 = eb.comm.hotp.hotpGetQrLink(response.hotpKey, {
			label: uname,
			web: "enigmabridge.com/testAuth",
			issuer: "EnigmaBridge",
			ctr:0,
			digits: templateHotpDigits,
			stripPadding: true
		});

		log("QR link: " + qrLink2);
		divQrCode.html("");
		divQrCode.qrcode(qrLink2);
	}

	// Update other fields.
	fldLoginUsername.val(uname);
	fldChangeUsername.val(uname);
	fldResetUsername.val(uname);
	if (record.isPasswd){
		fldChangeCurrentPassword.val(record.password);
	} else {
		// TODO: disable password change.
	}

	if (record.isPasswd && !record.isHotp){
		radLoginPassword.click();
	}

	// Store this record to the local database.
	userNameMap[uname] = record;
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

// ---------------------------------------------------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------------------------------------------------

function getUserRecord(uname){
	return userNameMap[uname];
}

function btnPasswordGenClick(correctOne){
	var uname = fldLoginUsername.val();
	var record = getUserRecord(uname);
	if (record === undefined){
		statusFieldSet(fldLoginResult, 'User was not found', false);
		return;
	}

	var doHotp = isChecked(radLoginHotp);

	// If method change is enabled, change method first.
	if (doChangeAuthMethod){
		if (doHotp) {
			radLoginPassword.click();
		} else {
			radLoginHotp.click();
		}

		doHotp = isChecked(radLoginHotp);
	}

	doChangeAuthMethod = record.isPasswd && record.isHotp;
	if (!correctOne){
		if (doHotp){
			fldLoginPassword.val(sprintf("%06d", Math.floor(Math.random()*Math.pow(10, templateHotpDigits))));
		} else {
			fldLoginPassword.val('InvalidPassword' + Math.floor(Math.random()*100));
		}

		return;
	}

	if (doHotp && !record.isHotp){
		statusFieldSet(fldLoginResult, 'HOTP method not enabled for this user', false);
	}

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
	statusFieldSet(fldLoginResult, "Connection error", false);
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

	statusFieldSet(fldLoginResult, status, response.hotpStatus == eb.comm.status.SW_STAT_OK);

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
		statusFieldSet(fldLoginResult, "User was not found", false);
		return;
	}

	// Build request.
	statusFieldSet(fldLoginResult, "...");

	// Auth Request
	var doHotp = isChecked(radLoginHotp);
	var reqSettings = $.extend(requestConfig, {
		apiKeyLow4Bytes: 	doHotp ? svcSettings.auth.hotp.uiod : svcSettings.auth.password.uiod,
		userObjectId: 		doHotp ? svcSettings.auth.hotp.uiod : svcSettings.auth.password.uiod,
		callRequestType: 	doHotp ? svcSettings.auth.hotp.requestType : svcSettings.auth.password.requestType
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
	bodyProgress(true);

	request.doRequest();
}

// ---------------------------------------------------------------------------------------------------------------------
// Change password
// ---------------------------------------------------------------------------------------------------------------------

function getRandomPassword(){
	return eb.misc.genChecksumValue(Math.floor(Math.random()*1000), 4);
}

function btnChangeGenNewPasswordClick(){
	fldChangeNewPassword.val(getRandomPassword());
}

function changeResetFields(){
	fldChangeCtx.val('');
	fldChangeCtxCrc.val('');
}

function changeFailed(data){
	changeResetFields();
	statusFieldSet(fldChangeStatus, "Connection error", false);
}

function changeFinished(record, response){
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

	statusFieldSet(fldChangeStatus, status, response.hotpStatus == eb.comm.status.SW_STAT_OK);

	// Fail.
	if (responseStatus != eb.comm.status.SW_STAT_OK){
		changeResetFields();
		return;
	}

	// Success, happy path.
	record.ctx = sjcl.codec.hex.fromBits(response.hotpUserCtx);
	record.password = fldChangeNewPassword.val();

	// Update context values
	fldChangeCtx.val(record.ctx);
	updateCrc(fldChangeCtxCrc, record.ctx);
	fldLoginCtx.val(record.ctx);
	updateCrc(fldLoginCtxCrc, record.ctx);
}

function btnChangePasswordClick(){
	// Get user record.
	var uname = fldChangeUsername.val();
	var record = getUserRecord(uname);
	if (!record){
		statusFieldSet(fldChangeStatus, "User was not found", false);
		return;
	}

	// Build request.
	statusFieldSet(fldChangeStatus, '...');

	// Check current password
	if (fldChangeCurrentPassword.val() != record.password){
		statusFieldSet(fldChangeStatus, "Current password is invalid", false);
		return;
	}

	// Change password Request
	var reqSettings = $.extend(requestConfig, {
		apiKeyLow4Bytes: 	svcSettings.updateUser.uiod,
		userObjectId: 		svcSettings.updateUser.uiod,
		callRequestType: 	svcSettings.updateUser.requestType
	});
	var reqConfig = {hotp:{
		userId: record.userId,
		userCtx: record.ctx,
		method: eb.comm.hotp.USERAUTH_FLAG_PASSWD,
		passwd: sjcl.hash.sha256.hash(fldChangeNewPassword.val())
	}};

	var request = new eb.comm.hotp.authContextUpdateRequest(reqConfig);
	request.configure(reqSettings);
	request.logger = append_message;

	// Callbacks settings.
	request.done(function(response, requestObj, data) {
		log("DONE! " + response.toString());
		changeFinished(record, response);

	}).fail(function(failType, data){
		log("fail! type=" + failType);
		if (failType == eb.comm.status.PDATA_FAIL_RESPONSE_FAILED){
			log("Fail msg: " + data.response.toString());
			changeFinished(record, data.response);

		} else if (failType == eb.comm.status.PDATA_FAIL_CONNECTION){
			log("Connection error");
			changeFailed(data);
		}

	}).always(function(request, data){
		log("Change Request finished");
		bodyProgress(false);
	});

	// Build the request so we can display request in the form.
	request.build();

	// Do the call.
	statusFieldSet(fldChangeStatus, '...');
	bodyProgress(true);

	request.doRequest();
}

// ---------------------------------------------------------------------------------------------------------------------
// Reset authentication data
// ---------------------------------------------------------------------------------------------------------------------

function btnResetRandomPasswordClick(){
	fldResetPassword.val(getRandomPassword());
}

function resetResetFields(){
	fldResetQr.html('');
	fldResetCtx.val('');
	fldResetCtxCrc.val('');
}

function resetFailed(data){
	resetResetFields();
	statusFieldSet(fldResetStatus, "Connection error", false);
}

function resetFinished(record, response){
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

	statusFieldSet(fldResetStatus, status, response.hotpStatus == eb.comm.status.SW_STAT_OK);

	// Fail.
	if (responseStatus != eb.comm.status.SW_STAT_OK){
		resetResetFields();
		return;
	}

	// Success, happy path.
	record.ctx = sjcl.codec.hex.fromBits(response.hotpUserCtx);
	if (isChecked(radResetPassword)) {
		record.password = fldResetPassword.val();
	}

	if (response.hotpKey){
		record.counter = 1;
		record.secret = sjcl.codec.hex.fromBits(response.hotpKey);
		var qrLink2 = eb.comm.hotp.hotpGetQrLink(response.hotpKey, {
			label: record.username,
			web: "enigmabridge.com/testAuth",
			issuer: "EnigmaBridge",
			ctr:0,
			digits: templateHotpDigits,
			stripPadding: true
		});

		log("QR link: " + qrLink2);
		fldResetQr.html("");
		fldResetQr.qrcode(qrLink2);
	}

	// Update context values
	fldResetCtx.val(record.ctx);
	updateCrc(fldResetCtxCrc, record.ctx);
	fldLoginCtx.val(record.ctx);
	updateCrc(fldLoginCtxCrc, record.ctx);
}

function btnResetPasswordClick(){
	// Get user record.
	var uname = fldResetUsername.val();
	var record = getUserRecord(uname);
	if (!record){
		statusFieldSet(fldResetStatus, "User was not found", false);
		return;
	}

	// Build request.
	statusFieldSet(fldResetStatus, '...');

	// Change password Request
	var isHotp = isChecked(radResetHotp);
	var reqSettings = $.extend(requestConfig, {
		apiKeyLow4Bytes: 	svcSettings.updateUser.uiod,
		userObjectId: 		svcSettings.updateUser.uiod,
		callRequestType: 	svcSettings.updateUser.requestType
	});
	var reqConfig = {hotp:{
		userId: record.userId,
		userCtx: record.ctx,
		method: isHotp ? eb.comm.hotp.USERAUTH_FLAG_HOTP : eb.comm.hotp.USERAUTH_FLAG_PASSWD
	}};

	if (!isHotp){
		reqConfig.hotp.passwd = sjcl.hash.sha256.hash(fldResetPassword.val())
	}

	var request = new eb.comm.hotp.authContextUpdateRequest(reqConfig);
	request.configure(reqSettings);
	request.logger = append_message;

	// Callbacks settings.
	request.done(function(response, requestObj, data) {
		log("DONE! " + response.toString());
		resetFinished(record, response);

	}).fail(function(failType, data){
		log("fail! type=" + failType);
		if (failType == eb.comm.status.PDATA_FAIL_RESPONSE_FAILED){
			log("Fail msg: " + data.response.toString());
			resetFinished(record, data.response);

		} else if (failType == eb.comm.status.PDATA_FAIL_CONNECTION){
			log("Connection error");
			resetFailed(data);
		}

	}).always(function(request, data){
		log("Change Request finished");
		bodyProgress(false);
	});

	// Build the request so we can display request in the form.
	request.build();

	// Do the call.
	statusFieldSet(fldResetStatus, '...');
	bodyProgress(true);

	request.doRequest();
}

// ---------------------------------------------------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------------------------------------------------
function handleMethodRadio(){
	// Auth system changed - reset generated template.
	templateGenerated = false;
	statusFieldSet(templateField, '');
	setDisabled(fldRegUsername, true);
	setDisabled(fldRegPassword, true);

	// Auto regenerate
	if (doAutogenerateTemplateSettingsOnChange){
		btnGenerateTemplate();
	}
}

function resetPasswordsRadioHandle(){
	doChangeAuthMethod = false;
	fldLoginPassword.val('');
}

function handleResetRadio(){
	setDisabled(fldResetPassword, isChecked(radResetHotp));
}

// ---------------------------------------------------------------------------------------------------------------------
// onLoad
// ---------------------------------------------------------------------------------------------------------------------

$(function()
{
	htmlBody = $("body");
	logElem = $("#log");

	templateField = $('#systemtemplate');
	chkPassword = $('#ch-method-pwd');
	chkHotp = $('#ch-method-hotp');
	btnInitSystem = $("#btnSystemInit");

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

	// Main buttons handlers.
	btnInitSystem.click(btnGenerateTemplate);

	btnRegRandomUsername.click(btnGenNameClick);
	btnCreateUser.click(btnCreateUserClick);

	btnLoginPasswordOK.click(function(){
		btnPasswordGenClick(true);
	});

	btnLoginPasswordWrong.click(function(){
		btnPasswordGenClick(false);
	});

	btnLogin.click(btnLoginClick);

	btnChangeGenNewPassword.click(btnChangeGenNewPasswordClick);
	btnChangePassword.click(btnChangePasswordClick);

	btnResetRandomPassword.click(btnResetRandomPasswordClick);
	btnResetPassword.click(btnResetPasswordClick);

	// Convenience handlers
	chkPassword.click(handleMethodRadio);
	chkHotp.click(handleMethodRadio);

	radResetHotp.click(handleResetRadio);
	radResetPassword.click(handleResetRadio);

	radLoginHotp.click(resetPasswordsRadioHandle);
	radLoginPassword.click(resetPasswordsRadioHandle);

	// Defaults
	handleMethodRadio();

	// Default form validation, not used.
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
         }
	 });
});