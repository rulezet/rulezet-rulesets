rule DllInjection {
	meta:
		description = "Webshells Auto-generated - file DllInjection.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "a7b92283a5102886ab8aee2bc5c8d718"
		id = "8a57e122-fd00-57f3-94db-736c5bfd76db"
	strings:
		$s0 = "\\BDoor\\DllInjecti"
	condition:
		all of them
}