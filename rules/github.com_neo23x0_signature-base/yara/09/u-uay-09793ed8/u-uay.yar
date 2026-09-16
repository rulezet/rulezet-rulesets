rule u_uay {
	meta:
		description = "Webshells Auto-generated - file uay.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "abbc7b31a24475e4c5d82fc4c2b8c7c4"
		id = "6a670e19-6e53-5b13-aabf-fe74d48b9113"
	strings:
		$s1 = "exec \"c:\\WINDOWS\\System32\\freecell.exe"
		$s9 = "SYSTEM\\CurrentControlSet\\Services\\uay.sys\\Security"
	condition:
		1 of them
}