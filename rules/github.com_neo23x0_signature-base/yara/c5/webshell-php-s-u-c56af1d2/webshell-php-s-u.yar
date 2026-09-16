rule webshell_php_s_u {
	meta:
		description = "Web Shell - file s-u.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "efc7ba1a4023bcf40f5e912f1dd85b5a"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s6 = "<a href=\"?act=do\"><font color=\"red\">Go Execute</font></a></b><br /><textarea"
	condition:
		all of them
}