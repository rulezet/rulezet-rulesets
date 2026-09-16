rule EQGRP_BpfCreator_RHEL4 {
	meta:
		description = "EQGRP Toolset Firewall - file BpfCreator-RHEL4"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "bd7303393409623cabf0fcf2127a0b81fae52fe40a0d2b8db0f9f092902bbd92"
		id = "476185f2-b093-5fb9-8604-891e96fe52a9"
	strings:
		$s1 = "usage %s \"<tcpdump pcap string>\" <outfile>" fullword ascii
		$s2 = "error reading dump file: %s" fullword ascii
		$s3 = "truncated dump file; tried to read %u captured bytes, only got %lu" fullword ascii
		$s4 = "%s: link-layer type %d isn't supported in savefiles" fullword ascii
		$s5 = "DLT %d is not one of the DLTs supported by this device" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 2000KB and all of them )
}