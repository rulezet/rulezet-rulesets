rule WebShell_Uploader {
	meta:
		description = "PHP Webshells Github Archive - file Uploader.php"
		author = "Florian Roth"
		hash = "e216c5863a23fde8a449c31660fd413d77cce0b7"
	strings:
		$s1 = "move_uploaded_file($userfile, \"entrika.php\"); " fullword
	condition:
		all of them
}