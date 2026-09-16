rule HScan_v1_20_hscan {
	meta:
		description = "Chinese Hacktool Set - file hscan.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "568b06696ea0270ee1a744a5ac16418c8dacde1c"
		id = "4183824c-b77f-5500-a962-8d9dc78a9388"
	strings:
		$s1 = "[%s]: Found \"FTP account: anyone/anyone@any.net\"  !!!" fullword ascii
		$s2 = "%s -h 192.168.0.1 192.168.0.254 -port -ftp -max 200,100" fullword ascii
		$s3 = ".\\report\\%s-%s.html" fullword ascii
		$s4 = ".\\log\\Hscan.log" fullword ascii
		$s5 = "[%s]: Found cisco Enable password: %s !!!" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}