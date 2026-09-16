rule IDTools_For_WinXP_IdtTool_2 {
	meta:
		description = "Chinese Hacktool Set - file IdtTool.sys"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "07feb31dd21d6f97614118b8a0adf231f8541a67"
		id = "0312be49-c262-5143-abfc-02d428552b86"
	strings:
		$s0 = "\\Device\\devIdtTool" wide
		$s1 = "IoDeleteSymbolicLink" fullword ascii  
		$s3 = "IoDeleteDevice" fullword ascii  
		$s6 = "IoCreateSymbolicLink" fullword ascii 
		$s7 = "IoCreateDevice" fullword ascii 
	condition:
		uint16(0) == 0x5a4d and filesize < 7KB and all of them
}