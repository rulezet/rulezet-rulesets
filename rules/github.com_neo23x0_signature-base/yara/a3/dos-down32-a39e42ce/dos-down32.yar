rule Dos_Down32 {
	meta:
		description = "Chinese Hacktool Set - file Down32.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "0365738acd728021b0ea2967c867f1014fd7dd75"
		id = "e56c254d-1238-5786-8e8a-f9122b0310a9"
	strings:
		$s2 = "C:\\Windows\\Temp\\Cmd.txt" fullword wide
		$s6 = "down.exe" fullword wide
		$s15 = "get_Form1" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 137KB and all of them
}