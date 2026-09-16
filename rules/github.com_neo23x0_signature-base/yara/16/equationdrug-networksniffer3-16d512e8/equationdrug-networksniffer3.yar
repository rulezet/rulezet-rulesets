rule EquationDrug_NetworkSniffer3 {
	meta:
		description = "EquationDrug - Network Sniffer - tdip.sys"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		hash = "14599516381a9646cd978cf962c4f92386371040"
		id = "c6b1658b-cbc6-535a-a3a2-15ce3cf6e4f6"
	strings:
		$s0 = "Corporation. All rights reserved." fullword wide
		$s1 = "IP Transport Driver" fullword wide
		$s2 = "tdip.sys" fullword wide
		$s3 = "tdip.pdb" fullword ascii
	condition:
		all of them
}