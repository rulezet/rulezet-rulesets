rule churrasco {
	meta:
		description = "Chinese Hacktool Set - file churrasco.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a8d4c177948a8e60d63de9d0ed948c50d0151364"
		id = "99cb5a7a-85c1-57f5-b5b6-f0b1092e1e06"
	strings:
		$s1 = "Done, command should have ran as SYSTEM!" ascii
		$s2 = "Running command with SYSTEM Token..." ascii
		$s3 = "Thread impersonating, got NETWORK SERVICE Token: 0x%x" ascii
		$s4 = "Found SYSTEM token 0x%x" ascii
		$s5 = "Thread not impersonating, looking for another thread..." ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and 2 of them
}