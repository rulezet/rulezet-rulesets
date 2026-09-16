rule CN_Tools_Shiell {
	meta:
		description = "Chinese Hacktool Set - file Shiell.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b432d80c37abe354d344b949c8730929d8f9817a"
		id = "7ac7d79d-3f4e-54e7-bb97-ce94cbbb40a2"
	strings:
		$s1 = "C:\\Users\\Tong\\Documents\\Visual Studio 2012\\Projects\\Shift shell" ascii
		$s2 = "C:\\Windows\\System32\\Shiell.exe" fullword wide
		$s3 = "Shift shell.exe" fullword wide
		$s4 = "\" /v debugger /t REG_SZ /d \"" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1500KB and 2 of them
}