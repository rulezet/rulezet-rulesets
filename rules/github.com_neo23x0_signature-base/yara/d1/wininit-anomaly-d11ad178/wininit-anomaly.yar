rule wininit_ANOMALY {
	meta:
		description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file wininit.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2015/03/16"
		hash = "2de5c051c0d7d8bcc14b1ca46be8ab9756f29320"
		id = "a251984f-c667-55ec-8cc3-3888e80ddf1e"
	strings:
		$s1 = "Windows Start-Up Application" fullword wide
	condition:
		filename == "wininit.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}