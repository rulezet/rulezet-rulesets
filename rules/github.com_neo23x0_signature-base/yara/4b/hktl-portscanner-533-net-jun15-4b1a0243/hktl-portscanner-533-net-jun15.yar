rule HKTL_Portscanner_533_NET_Jun15 {
	meta:
		description = "Chinese Hacktool Set - file portscanner.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		old_rule_name = "portscanner"
		date = "2015-06-13"
		hash = "1de367d503fdaaeee30e8ad7c100dd1e320858a4"
		id = "c834203d-6d4d-5242-9b1e-b64fa6560ccd"
	strings:
		$s0 = "PortListfNo" fullword ascii
		$s1 = ".533.net" fullword ascii
		$s2 = "CRTDLL.DLL" fullword ascii
		$s3 = "exitfc" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 25KB and all of them
}