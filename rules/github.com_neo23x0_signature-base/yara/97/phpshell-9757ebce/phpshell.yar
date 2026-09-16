rule PhpShell {
	meta:
		description = "Webshells Auto-generated - file PhpShell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "539baa0d39a9cf3c64d65ee7a8738620"
		id = "887264d3-5704-5e38-b0a6-44d529258ea2"
	strings:
		$s2 = "href=\"http://www.gimpster.com/wiki/PhpShell\">www.gimpster.com/wiki/PhpShell</a>."
	condition:
		all of them
}