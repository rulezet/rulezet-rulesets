rule Win32_klock {
	meta:
		description = "Chinese Hacktool Set - file klock.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "7addce4434670927c4efaa560524680ba2871d17"
		id = "dd17a8e2-54af-5967-937a-d83feceab891"
	strings:
		$s1 = "klock.dll" fullword ascii
		$s2 = "Erreur : impossible de basculer le bureau ; SwitchDesktop : " fullword wide
		$s3 = "klock de mimikatz pour Windows" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and all of them
}