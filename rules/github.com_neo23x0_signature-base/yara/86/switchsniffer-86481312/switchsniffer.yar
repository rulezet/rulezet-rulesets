rule SwitchSniffer {
	meta:
		description = "Chinese Hacktool Set - file SwitchSniffer.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1e7507162154f67dff4417f1f5d18b4ade5cf0cd"
		id = "6019f042-10ab-5899-8b1b-28b2609e9623"
	strings:
		$s0 = "NextSecurity.NET" fullword wide
		$s2 = "SwitchSniffer Setup" fullword wide
	condition:
		uint16(0) == 0x5a4d and all of them
}