rule arpsniffer {
	meta:
		description = "Chinese Hacktool Set - file arpsniffer.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "7d8753f56fc48413fc68102cff34b6583cb0066c"
		id = "78db3b18-008a-5a4e-9504-0cbe3b852046"
	strings:
		$s1 = "SHELL" ascii
		$s2 = "PacketSendPacket" fullword ascii
		$s3 = "ArpSniff" ascii
		$s4 = "pcap_loop" fullword ascii  
		$s5 = "packet.dll" fullword ascii  
	condition:
		uint16(0) == 0x5a4d and filesize < 120KB and all of them
}