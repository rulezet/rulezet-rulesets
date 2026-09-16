rule Ms_Viru_racle {
	meta:
		description = "Chinese Hacktool Set - file racle.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "13116078fff5c87b56179c5438f008caf6c98ecb"
		id = "bdc78dcc-79e6-5516-bba2-54bf537eae38"
	strings:
		$s0 = "PsInitialSystemProcess @%p" fullword ascii
		$s1 = "PsLookupProcessByProcessId(%u) Failed" fullword ascii
		$s2 = "PsLookupProcessByProcessId(%u) => %p" fullword ascii
		$s3 = "FirstStage() Loaded, CurrentThread @%p Stack %p - %p" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 210KB and all of them
}