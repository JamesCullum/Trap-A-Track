<?php
if(!isset($_FILES["report"])) {
	http_response_code(400);
	die("no report attached");
}

if($_FILES['report']['size'] > 52428800) {
	// 50 MB cap
	http_response_code(413);
	die("report too large");
}

move_uploaded_file($_FILES['report']['tmp_name'], "./reports/".$_SERVER['REMOTE_ADDR']."-".time().".zip");

mail("test@example.com", "Trap-A-Track triggered", "Trap-A-Track has been triggered! Please take a look at the server to retrieve the details.");
echo "done";