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
	});

	$("#datahex").keyup(function(evt) {
		var src = $("#datahex");
		var dst = $("#dataraw");
		dst.val(hexCodedToRaw(src, evt));
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