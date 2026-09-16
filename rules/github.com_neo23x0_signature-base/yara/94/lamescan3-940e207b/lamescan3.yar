rule lamescan3 {
	meta:
		description = "Chinese Hacktool Set - file lamescan3.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "3130eefb79650dab2e323328b905e4d5d3a1d2f0"
		id = "8ff1a0e6-d054-589d-a038-f889951ba250"
	strings:
		$s1 = "dic\\loginlist.txt" fullword ascii
		$s2 = "Radmin.exe" fullword ascii
		$s3 = "lamescan3.pdf!" fullword ascii
		$s4 = "dic\\passlist.txt" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3740KB and all of them
}