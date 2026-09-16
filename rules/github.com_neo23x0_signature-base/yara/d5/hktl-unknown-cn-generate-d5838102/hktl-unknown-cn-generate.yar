rule HKTL_Unknown_CN_Generate {
	meta:
		description = "Chinese Hacktool Set - file Generate.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		modified = "2022-01-20" 
		hash = "2cb4c3916271868c30c7b4598da697f59e9c7a12"
		id = "88ad2c71-519f-58b0-87f8-a6f54a54a774"
	strings:
		$s1 = "C:\\TEMP\\" ascii
		$s2 = "Connection Closed Gracefully.;Could not bind socket. Address and port are alread" wide
		$s3 = "$530 Please login with USER and PASS." fullword ascii
		$s4 = "_Shell.exe" fullword ascii
		$s5 = "ftpcWaitingPassword" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and 3 of them
}