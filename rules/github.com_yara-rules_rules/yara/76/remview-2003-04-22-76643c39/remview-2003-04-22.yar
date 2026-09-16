rule remview_2003_04_22 {
	meta:
		description = "Webshells Auto-generated - file remview_2003_04_22.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "17d3e4e39fbca857344a7650f7ea55e3"
	strings:
		$s1 = "\"<b>\".mm(\"Eval PHP code\").\"</b> (\".mm(\"don't type\").\" \\\"&lt;?\\\""
	condition:
		all of them
}