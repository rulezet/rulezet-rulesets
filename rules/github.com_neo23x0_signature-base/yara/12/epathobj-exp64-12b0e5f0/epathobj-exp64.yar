rule epathobj_exp64 {
	meta:
		description = "Chinese Hacktool Set - file epathobj_exp64.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		modified = "2022-12-21"
		hash = "09195ba4e25ccce35c188657957c0f2c6a61d083"
		id = "cb56bbdc-8afa-5b4b-b7df-942dd3d60366"
	strings:
		$s1 = "Watchdog thread %d waiting on Mutex" fullword ascii
		$s2 = "Exploit ok run command" fullword ascii
		$s3 = "\\epathobj_exp\\x64\\Release\\epathobj_exp.pdb" ascii
		$s4 = "Alllocated userspace PATHRECORD () %p" fullword ascii
		$s5 = "Mutex object did not timeout, list not patched" fullword ascii
		$s6 = "- inconsistent onexit begin-end variables" fullword wide  
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and 2 of them
}