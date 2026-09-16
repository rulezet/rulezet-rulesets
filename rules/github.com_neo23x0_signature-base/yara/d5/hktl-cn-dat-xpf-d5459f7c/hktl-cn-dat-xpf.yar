rule HKTL_CN_dat_xpf {
	meta:
		description = "Chinese Hacktool Set - file xpf.sys"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		modified = "2023-01-06"
		old_rule_name = "dat_xpf"
		hash = "761125ab594f8dc996da4ce8ce50deba49c81846"
		id = "fe2de535-4f86-5c29-b67e-153423a897f7"
	strings:
		$s1 = "UnHook IoGetDeviceObjectPointer ok!" fullword ascii
		$s2 = "\\Device\\XScanPF" wide
		$s3 = "\\DosDevices\\XScanPF" wide
	condition:
		uint16(0) == 0x5a4d and filesize < 25KB and all of them
}