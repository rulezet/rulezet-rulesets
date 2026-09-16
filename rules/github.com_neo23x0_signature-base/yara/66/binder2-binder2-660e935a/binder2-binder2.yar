rule binder2_binder2 {
	meta:
		description = "Webshells Auto-generated - file binder2.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "d594e90ad23ae0bc0b65b59189c12f11"
		id = "29269dc0-f2e4-56ec-ad64-0dff00e339b7"
	strings:
		$s0 = "IsCharAlphaNumericA"
		$s2 = "WideCharToM"
		$s4 = "g 5pur+virtu!"
		$s5 = "\\syslog.en"
		$s6 = "heap7'7oqk?not="
		$s8 = "- Kablto in"
	condition:
		all of them
}