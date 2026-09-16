import "pe"
rule nspack13
{
	meta:
		author = "PEiD"
		description = "nSPack 1.3 -> North Star/Liu Xing Ping"
		group = "444"
		function = "0"
	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 ?? ?? FF FF 8B 06 83 F8 00 74 11 8D B5 ?? ?? FF FF 8B 06 83 F8 01 0F 84 F1 01 }
	condition:
		$a0 at pe.entry_point
}