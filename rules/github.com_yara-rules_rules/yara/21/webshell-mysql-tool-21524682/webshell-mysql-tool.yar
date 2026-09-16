rule WebShell_mysql_tool {
	meta:
		description = "PHP Webshells Github Archive - file mysql_tool.php"
		author = "Florian Roth"
		hash = "c9cf8cafcd4e65d1b57fdee5eef98f0f2de74474"
	strings:
		$s12 = "$dump .= \"-- Dumping data for table '$table'\\n\";" fullword
		$s20 = "$dump .= \"CREATE TABLE $table (\\n\";" fullword
	condition:
		2 of them
}