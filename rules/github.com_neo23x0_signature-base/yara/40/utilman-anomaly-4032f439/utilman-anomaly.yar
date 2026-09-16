rule Utilman_ANOMALY {
	meta:
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		description = "Abnormal utilman.exe - typical strings not found in file"
		date = "01/06/2014"
		score = 70
		id = "98daff9b-1600-56b3-87ff-637deaa6808c"
	strings:
		$win7 = "utilman.exe" wide fullword
		$win2000 = "Start with Utility Manager" fullword wide
		$win2012 = "utilman2.exe" fullword wide
	condition:
		( filename == "utilman.exe" or filename == "Utilman.exe" )
      and uint16(0) == 0x5a4d
      and not 1 of ($win*) and not WINDOWS_UPDATE_BDC
}