rule Mithozhan_Trojan {
	meta:
		description = "Mitozhan Trojan used in APT Terracotta"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
		date = "2015-08-04"
		score = 70
		hash = "8553b945e2d4b9f45c438797d6b5e73cfe2899af1f9fd87593af4fd7fb51794a"
		id = "5e2b4e08-1a35-5eb0-8c25-a73d45b0e279"
	strings:
		$s1 = "adbrowser" fullword wide 
		$s2 = "IJKLlGdmaWhram0vn36BgIOChYR3L45xcHNydXQvhmloa2ptbH8voYCDTw==" fullword ascii
		$s3 = "EFGHlGdmaWhrL41sf36BgIOCL6R3dk8=" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}