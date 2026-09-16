rule epathobj_exp32 {
	meta:
		description = "Chinese Hacktool Set - file epathobj_exp32.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		modified = "2022-12-21"
		hash = "ed86ff44bddcfdd630ade8ced39b4559316195ba"
		id = "ca4639af-ee4f-5220-9595-e7a06b9a8534"
	strings:
		$s0 = "Watchdog thread %d waiting on Mutex" fullword ascii
		$s1 = "Exploit ok run command" fullword ascii
		$s2 = "\\epathobj_exp\\Release\\epathobj_exp.pdb" ascii
		$s3 = "Alllocated userspace PATHRECORD () %p" fullword ascii
		$s4 = "Mutex object did not timeout, list not patched" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 270KB and all of them
}