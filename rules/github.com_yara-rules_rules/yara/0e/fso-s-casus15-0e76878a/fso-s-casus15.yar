rule FSO_s_casus15 {
	meta:
		description = "Webshells Auto-generated - file casus15.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "8d155b4239d922367af5d0a1b89533a3"
	strings:
		$s6 = "if((is_dir(\"$deldir/$file\")) AND ($file!=\".\") AND ($file!=\"..\"))"
	condition:
		all of them
}