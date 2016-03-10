<?php	
	if(empty($_POST['data_encrypt']) || empty($_POST['']) || empty($_POST['']) || empty($_POST['']))
	{
		return false;
	}
	
	$data_encrypt = $_POST['data_encrypt'];
	$ = $_POST[''];
	$ = $_POST[''];
	$ = $_POST[''];
	
	$to = 'receiver@yoursite.com'; // Email submissions are sent to this email

	// Create email	
	$email_subject = "Message from testwebpage.";
	$email_body = "You have received a new message. \n\n".
				  "Data_Encrypt: $data_encrypt \n: $ \n: $ \n: $ \n";
	$headers = "From: contact@yoursite.com\n";
	$headers .= "Reply-To: DoNotReply@yoursite.com";	
	
	mail($to,$email_subject,$email_body,$headers); // Post message
	return true;			
?>