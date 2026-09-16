rule FSO_s_test {
	meta:
		description = "Webshells Auto-generated - file test.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "82cf7b48da8286e644f575b039a99c26"
		id = "b0cc5a2a-c741-50dd-854f-5a43769e8f47"
	strings:
		$s0 = "$yazi = \"test\" . \"\\r\\n\";"
		$s2 = "fwrite ($fp, \"$yazi\");"
	condition:
		all of them
}