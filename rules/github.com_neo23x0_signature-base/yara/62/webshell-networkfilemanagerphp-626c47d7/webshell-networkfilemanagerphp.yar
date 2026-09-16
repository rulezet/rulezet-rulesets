rule webshell_NetworkFileManagerPHP {
	meta:
		description = "Web Shell - file NetworkFileManagerPHP.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "acdbba993a5a4186fd864c5e4ea0ba4f"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s9 = "  echo \"<br><center>All the data in these tables:<br> \".$tblsv.\" were putted "
	condition:
		all of them
}