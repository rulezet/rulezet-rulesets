rule FreeVersion_release {
	meta:
		description = "Chinese Hacktool Set - file release.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f42e4b5748e92f7a450eb49fc89d6859f4afcebb"
		id = "1a603634-a00a-5f8b-a47d-c3c8065a5c3e"
	strings:
		$s1 = "-->Got WMI process Pid: %d " ascii
		$s2 = "This exploit will execute \"net user " ascii
		$s3 = "net user temp 123456 /add & net localgroup administrators temp /add" fullword ascii
		$s4 = "Running reverse shell" ascii
		$s5 = "wmiprvse.exe" fullword ascii
		$s6 = "SELECT * FROM IIsWebInfo" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 3 of them
}