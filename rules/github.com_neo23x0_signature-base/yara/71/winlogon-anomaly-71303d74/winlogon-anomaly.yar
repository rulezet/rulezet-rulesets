rule winlogon_ANOMALY {
	meta:
		description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file winlogon.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2015/03/16"
		hash = "af210c8748d77c2ff93966299d4cd49a8c722ef6"
		id = "ee424459-8048-52b8-ba97-4d09265a881f"
	strings:
		$s1 = "AuthzAccessCheck failed" fullword
		$s2 = "Windows Logon Application" fullword wide
	condition:
		filename == "winlogon.exe"
      and not 1 of ($s*)
      and uint16(0) == 0x5a4d
		and not WINDOWS_UPDATE_BDC
		and not filepath contains "Malwarebytes"
}