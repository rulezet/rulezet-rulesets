rule CN_Honker_IIS6_iis6 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file iis6.com"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f0c9106d6d2eea686fd96622986b641968d0b864"
		id = "f5d49cbd-1aec-5126-ab5d-83e485fa6869"
	strings:
		$s0 = "GetMod;ul" fullword ascii
		$s1 = "excjpb" fullword ascii
		$s2 = "LEAUT1" fullword ascii
		$s3 = "EnumProcessModules" fullword ascii  
	condition:
		uint16(0) == 0x5a4d and filesize < 50KB and all of them
}