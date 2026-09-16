rule GoodToolset_ms11011 {
	meta:
		description = "Chinese Hacktool Set - file ms11011.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5ad7a4962acbb6b0e3b73d77385eb91feb88b386"
		id = "689b7ea3-6707-5f99-8232-438d903d414d"
	strings:
		$s0 = "\\i386\\Hello.pdb" ascii
		$s1 = "OS not supported." fullword ascii
		$s3 = "Not supported." fullword wide  
		$s4 = "SystemDefaultEUDCFont" fullword wide  
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}