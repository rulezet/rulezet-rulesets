rule kelloworld_2 {
	meta:
		description = "Chinese Hacktool Set - file kelloworld.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "55d5dabd96c44d16e41f70f0357cba1dda26c24f"
		id = "3f298004-e618-5f4a-9cd7-c7c954b6fc64"
	strings:
		$s1 = "Hello World!" fullword wide
		$s2 = "kelloworld.dll" fullword ascii
		$s3 = "kelloworld de mimikatz pour Windows" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}