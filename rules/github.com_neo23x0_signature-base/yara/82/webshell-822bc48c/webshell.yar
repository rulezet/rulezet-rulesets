rule webshell {
	meta:
		description = "Webshells Auto-generated - file webshell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "f2f8c02921f29368234bfb4d4622ad19"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "RhViRYOzz"
		$s1 = "d\\O!jWW"
		$s2 = "bc!jWW"
		$s3 = "0W[&{l"
		$s4 = "[INhQ@\\"
	condition:
		all of them
}