rule Apolmy_Privesc_Trojan {
	meta:
		description = "Apolmy Privilege Escalation Trojan used in APT Terracotta"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
		date = "2015-08-04"
		score = 80
		hash = "d7bd289e6cee228eb46a1be1fcdc3a2bd5251bc1eafb59f8111756777d8f373d"
		id = "2f3f496b-ebfe-5a6e-89ad-a24af6378fd7"
	strings:
		$s1 = "[%d] Failed, %08X" fullword ascii
		$s2 = "[%d] Offset can not fetched." fullword ascii
		$s3 = "PowerShadow2011" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}