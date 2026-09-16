rule webshell_NetworkFileManagerPHP {
	meta:
		description = "Web Shell - file NetworkFileManagerPHP.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "acdbba993a5a4186fd864c5e4ea0ba4f"
	strings:
		$s9 = "  echo \"<br><center>All the data in these tables:<br> \".$tblsv.\" were putted "
	condition:
		all of them
}