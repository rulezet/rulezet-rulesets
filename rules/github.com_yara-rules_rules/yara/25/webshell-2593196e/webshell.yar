rule webshell {
	meta:
		description = "Webshells Auto-generated - file webshell.php"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "f2f8c02921f29368234bfb4d4622ad19"
	strings:
		$s0 = "RhViRYOzz"
		$s1 = "d\\O!jWW"
		$s2 = "bc!jWW"
		$s3 = "0W[&{l"
		$s4 = "[INhQ@\\"
	condition:
		all of them
}