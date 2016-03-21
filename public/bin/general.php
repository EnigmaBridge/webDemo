<?php	
	if(empty($_POST['aes256']) || empty($_POST['rsa1024']) || empty($_POST['rsa2048']) || empty($_POST['dataraw']) || empty($_POST['datahex']) || empty($_POST['allzeroes']) || empty($_POST['lowercasea']) || empty($_POST['testvector']) || empty($_POST['testvector1k']) || empty($_POST['lowercasea1k']) || empty($_POST['enigma1k']) || empty($_POST['testvector2k']) || empty($_POST['lowercasea2k']) || empty($_POST['enigma2k']) || empty($_POST['dragonfly']) || empty($_POST['damselfly']) || empty($_POST['request']) || empty($_POST['responsetime']) || empty($_POST['responsehex']) || empty($_POST['responseraw']))
	{
		return false;
	}
	
	$aes256 = $_POST['aes256'];
	$rsa1024 = $_POST['rsa1024'];
	$rsa2048 = $_POST['rsa2048'];
	$dataraw = $_POST['dataraw'];
	$datahex = $_POST['datahex'];
	$allzeroes = $_POST['allzeroes'];
	$lowercasea = $_POST['lowercasea'];
	$testvector = $_POST['testvector'];
	$testvector1k = $_POST['testvector1k'];
	$lowercasea1k = $_POST['lowercasea1k'];
	$enigma1k = $_POST['enigma1k'];
	$testvector2k = $_POST['testvector2k'];
	$lowercasea2k = $_POST['lowercasea2k'];
	$enigma2k = $_POST['enigma2k'];
	$dragonfly = $_POST['dragonfly'];
	$damselfly = $_POST['damselfly'];
	$request = $_POST['request'];
	$responsetime = $_POST['responsetime'];
	$responsehex = $_POST['responsehex'];
	$responseraw = $_POST['responseraw'];
	
	$to = 'receiver@yoursite.com'; // Email submissions are sent to this email

	// Create email	
	$email_subject = "Message from testwebpage.";
	$email_body = "You have received a new message. \n\n".
				  "Aes256: $aes256 \nRsa1024: $rsa1024 \nRsa2048: $rsa2048 \nDataraw: $dataraw \nDatahex: $datahex \nAllzeroes: $allzeroes \nLowercasea: $lowercasea \nTestvector: $testvector \nTestvector1K: $testvector1k \nLowercasea1K: $lowercasea1k \nEnigma1K: $enigma1k \nTestvector2K: $testvector2k \nLowercasea2K: $lowercasea2k \nEnigma2K: $enigma2k \nDragonfly: $dragonfly \nDamselfly: $damselfly \nRequest: $request \nResponsetime: $responsetime \nResponsehex: $responsehex \nResponseraw: $responseraw \n";
	$headers = "From: contact@yoursite.com\n";
	$headers .= "Reply-To: DoNotReply@yoursite.com";	
	
	mail($to,$email_subject,$email_body,$headers); // Post message
	return true;			
?>