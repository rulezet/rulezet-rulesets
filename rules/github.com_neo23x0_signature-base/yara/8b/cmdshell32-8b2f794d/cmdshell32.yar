rule Cmdshell32 {
	meta:
		description = "Chinese Hacktool Set - file Cmdshell32.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "3c41116d20e06dcb179e7346901c1c11cd81c596"
		id = "f1dfb5a1-4292-5895-8310-913cfdf4d9d0"
	strings:
		$s1 = "cmdshell.exe" fullword wide
		$s2 = "cmdshell" fullword ascii
		$s3 = "[Root@CmdShell ~]#" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 62KB and all of them
}