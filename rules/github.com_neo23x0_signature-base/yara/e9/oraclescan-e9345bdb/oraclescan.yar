rule OracleScan {
	meta:
		description = "Chinese Hacktool Set - file OracleScan.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "10ff7faf72fe6da8f05526367b3522a2408999ec"
		id = "142c0ed1-0752-54c3-9a4b-68e656c32939"
	strings:
		$s1 = "MYBLOG:HTTP://HI.BAIDU.COM/0X24Q" fullword ascii
		$s2 = "\\Borland\\Delphi\\RTL" ascii
		$s3 = "USER_NAME" ascii
		$s4 = "FROMWWHERE" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}