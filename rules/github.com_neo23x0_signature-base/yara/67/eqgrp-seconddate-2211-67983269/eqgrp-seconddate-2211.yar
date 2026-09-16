rule EQGRP_SecondDate_2211 {
	meta:
		description = "EQGRP Toolset Firewall - file SecondDate-2211.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "2337d0c81474d03a02c404cada699cf1b86c3c248ea808d4045b86305daa2607"
		id = "00951270-6189-58b6-8b64-422c4ab15ebe"
	strings:
		$s1 = "SD_processControlPacket" fullword ascii
		$s2 = "Encryption_rc4SetKey" fullword ascii
		$s3 = ".got_loader" fullword ascii
		$s4 = "^GET.*(?:/ |\\.(?:htm|asp|php)).*\\r\\n" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 200KB and all of them )
}