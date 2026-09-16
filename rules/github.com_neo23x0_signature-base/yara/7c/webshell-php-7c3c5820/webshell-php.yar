rule webshell_php {
	meta:
		description = "Semi-Auto-generated  - file webshell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "e425241b928e992bde43dd65180a4894"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s2 = "<die(\"Couldn't Read directory, Blocked!!!\");"
		$s3 = "PHP Web Shell"
	condition:
		all of them
}