<?php print "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\" ?>\n"; ?>
<!DOCTYPE html
    PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
    <title>
        Hello, world!
    </title>
</head>
<body>
<h1>Hello, world!</h1>
<p>Aloha!</p>
<?php
	function getServerPort() {
		if (array_key_exists('HTTP_X_FORWARDED_PORT', $_SERVER)) {
			return $_SERVER["HTTP_X_FORWARDED_PORT"];
		} else if (array_key_exists('SERVER_PORT', $_SERVER)) {
			return $_SERVER["SERVER_PORT"];
		} else {
			return "80";
		}
	}

	$ip = $_SERVER["HTTP_HOST"];

	$scheme = getServerPort() == "443" ? "https" : "http";

	$logged_out_uri = urlencode("$scheme://$ip/loggedout.php");
?>
<p><a href="/redirect_uri?logout=<?=$logged_out_uri?>">Logout</a></p>
<div class="footer">
    <p>&copy; Copyright Jonathan Harden 2020</p>
<p>
	<a href="http://validator.w3.org/check?uri=referer">
		<img src="images/valid_xhtml_1_0.png" alt="Valid XHTML 1.0 Strict" height="31" width="88" />
	</a>
</p>
</div>
</body>
</html>
