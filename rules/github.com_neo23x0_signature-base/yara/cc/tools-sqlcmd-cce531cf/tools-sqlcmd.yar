rule tools_Sqlcmd {
	meta:
		description = "Chinese Hacktool Set - file Sqlcmd.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "99d56476e539750c599f76391d717c51c4955a33"
		id = "26e29826-d4bb-55d0-9331-a91e4473daca"
	strings:
		$s0 = "[Usage]:  %s <HostName|IP> <UserName> <Password>" fullword ascii
		$s1 = "=============By uhhuhy(Feb 18,2003) - http://www.cnhonker.net=============" fullword ascii 
		$s4 = "Cool! Connected to SQL server on %s successfully!" fullword ascii
		$s5 = "EXEC master..xp_cmdshell \"%s\"" fullword ascii
		$s6 = "=======================Sqlcmd v0.21 For HScan v1.20=======================" fullword ascii
		$s10 = "Error,exit!" fullword ascii
		$s11 = "Sqlcmd>" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 40KB and 3 of them
}