rule webshell_MySQL_Web_Interface_Version_0_8 {
	meta:
		description = "Web Shell - file MySQL Web Interface Version 0.8.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "36d4f34d0a22080f47bb1cb94107c60f"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s2 = "href='$PHP_SELF?action=dumpTable&dbname=$dbname&tablename=$tablename'>Dump</a>"
	condition:
		all of them
}