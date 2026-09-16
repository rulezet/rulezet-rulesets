rule OtherTools_xiaoa {
	meta:
		description = "Chinese Hacktool Set - file xiaoa.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6988acb738e78d582e3614f83993628cf92ae26d"
		id = "a456d373-2063-5264-8cf4-d0a5918392fc"
	strings:
		$s1 = "Usage:system_exp.exe \"cmd\"" fullword ascii
		$s2 = "The shell \"cmd\" success!" fullword ascii
		$s3 = "Not Windows NT family OS." fullword ascii 
		$s4 = "Unable to get kernel base address." fullword ascii
		$s5 = "run \"%s\" failed,code: %d" fullword ascii
		$s6 = "Windows Kernel Local Privilege Exploit " fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}