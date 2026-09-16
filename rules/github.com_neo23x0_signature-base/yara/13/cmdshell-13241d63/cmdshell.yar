rule cmdShell {
	meta:
		description = "Webshells Auto-generated - file cmdShell.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "8a9fef43209b5d2d4b81dfbb45182036"
		id = "be256fc4-8dc5-58e4-9ca2-5a1df936b8dd"
	strings:
		$s1 = "if cmdPath=\"wscriptShell\" then"
	condition:
		all of them
}