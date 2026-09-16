rule dbgntboot {
	meta:
		description = "Webshells Auto-generated - file dbgntboot.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "4d87543d4d7f73c1529c9f8066b475ab"
		id = "6b9381e6-597d-5e74-a318-9931d20a9d08"
	strings:
		$s2 = "now DOS is working at mode %d,faketype %d,against %s,has worked %d minutes,by sp"
		$s3 = "sth junk the M$ Wind0wZ retur"
	condition:
		all of them
}