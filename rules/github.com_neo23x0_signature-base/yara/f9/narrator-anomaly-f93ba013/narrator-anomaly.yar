rule narrator_ANOMALY {
	meta:
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		description = "Abnormal narrator.exe - typical strings not found in file"
		date = "01/06/2014"
		score = 55
		id = "a51f1916-f89a-58a9-b65c-91bf99575b80"
	strings:
		$win7 = "Microsoft-Windows-Narrator" wide fullword
		$win2000 = "&About Narrator..." wide fullword
		$win2012 = "Screen Reader" wide fullword
		$winxp = "Software\\Microsoft\\Narrator"
		$winxp_en = "SOFTWARE\\Microsoft\\Speech\\Voices" wide
	condition:
		filename == "narrator.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($win*) and not WINDOWS_UPDATE_BDC
}