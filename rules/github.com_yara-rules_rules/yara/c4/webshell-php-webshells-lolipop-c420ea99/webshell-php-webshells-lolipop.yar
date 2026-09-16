rule WebShell_php_webshells_lolipop {
	meta:
		description = "PHP Webshells Github Archive - file lolipop.php"
		author = "Florian Roth"
		hash = "86f23baabb90c93465e6851e40104ded5a5164cb"
	strings:
		$s3 = "$commander = $_POST['commander']; " fullword
		$s9 = "$sourcego = $_POST['sourcego']; " fullword
		$s20 = "$result = mysql_query($loli12) or die (mysql_error()); " fullword
	condition:
		all of them
}