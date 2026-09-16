rule x64_KiwiCmd {
	meta:
		description = "Chinese Hacktool Set - file KiwiCmd.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "569ca4ff1a5ea537aefac4a04a2c588c566c6d86"
		id = "df759fd4-5d42-5dd9-81d0-ceccafcdd64d"
	strings:
		$s1 = "Process Ok, Memory Ok, resuming process :)" fullword wide
		$s2 = "Kiwi Cmd no-gpo" fullword wide
		$s3 = "KiwiAndCMD" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 400KB and 2 of them
}