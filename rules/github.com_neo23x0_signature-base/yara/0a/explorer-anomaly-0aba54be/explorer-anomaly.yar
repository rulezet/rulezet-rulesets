rule explorer_ANOMALY {
	meta:
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		description = "Abnormal explorer.exe - typical strings not found in file"
		date = "27/05/2014"
		score = 55
		id = "ecadd78f-21a1-5a9f-8f3f-cb51e872805b"
	strings:
		$s1 = "EXPLORER.EXE" wide fullword
		$s2 = "Windows Explorer" wide fullword
	condition:
		filename == "explorer.exe"
      and uint16(0) == 0x5a4d
      and not filepath contains "teamviewer"
      and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}