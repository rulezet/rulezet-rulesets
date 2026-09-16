rule iMHaPFtp {
	meta:
		description = "Webshells Auto-generated - file iMHaPFtp.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "12911b73bc6a5d313b494102abcf5c57"
	strings:
		$s1 = "echo \"\\t<th class=\\\"permission_header\\\"><a href=\\\"$self?{$d}sort=permission$r\\\">"
	condition:
		all of them
}