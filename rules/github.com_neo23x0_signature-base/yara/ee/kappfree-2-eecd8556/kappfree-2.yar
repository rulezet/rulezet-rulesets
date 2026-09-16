rule kappfree_2 {
	meta:
		description = "Chinese Hacktool Set - file kappfree.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5d578df9a71670aa832d1cd63379e6162564fb6b"
		id = "6c7b4a99-b5ab-5fd6-b130-7c30b84b7171"
	strings:
		$s1 = "kappfree.dll" fullword ascii
		$s2 = "kappfree de mimikatz pour Windows (anti AppLocker)" fullword wide
		$s3 = "' introuvable !" fullword wide
		$s4 = "kiwi\\mimikatz" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}