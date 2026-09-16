rule kappfree {
	meta:
		description = "Chinese Hacktool Set - file kappfree.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e57e79f190f8a24ca911e6c7e008743480c08553"
		id = "eb9c1324-5d82-57ab-bd48-98c984b45b32"
	strings:
		$s1 = "Bienvenue dans un processus distant" fullword wide
		$s2 = "kappfree.dll" fullword ascii
		$s3 = "kappfree de mimikatz pour Windows (anti AppLocker)" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}