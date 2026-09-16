rule vanquish_2 {
	meta:
		description = "Webshells Auto-generated - file vanquish.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "2dcb9055785a2ee01567f52b5a62b071"
		id = "6736cad6-cba1-5b6f-ae05-e2b980280479"
	strings:
		$s2 = "Vanquish - DLL injection failed:"
	condition:
		all of them
}