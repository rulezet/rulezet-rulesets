rule osk_ANOMALY {
	meta:
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		description = "Abnormal osk.exe (On Screen Keyboard) - typical strings not found in file"
		date = "01/06/2014"
		score = 55
		id = "6b78b001-f863-5a24-a9d1-ee5e8305766b"
	strings:
		$s1 = "Accessibility On-Screen Keyboard" wide fullword
		$s2 = "\\oskmenu" wide fullword
		$s3 = "&About On-Screen Keyboard..." wide fullword
		$s4 = "Software\\Microsoft\\Osk" wide
	condition:
		filename == "osk.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}