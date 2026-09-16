import "pe"
rule perplex101dev_h
{
	meta:
		author = "PEiD"
		description = "Perplex PE-Protector 1.01dev -> [tC]/PERPLEX"
		group = "195"
		function = "0"
	strings:
		$a0 = { E8 51 00 00 00 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 E8 01 00 00 00 9A 59 8D 95 CD 25 40 00 E8 01 00 00 00 69 58 66 BF 4D 4A E8 2E 00 00 00 8D 52 F9 E8 01 00 00 00 E8 5B 68 CC FF E2 9A FF E4 69 FF A5 AF 2F 40 00 E9 E8 B9 FF FF FF EB 03 C7 84 E8 51 C3 EB 03 C7 84 9A 59 41 EB F0 E8 01 00 00 00 9A 59 EB 02 0F E8 E8 01 00 00 00 69 58 E8 00 00 00 00 5D 81 ED F9 25 40 00 }
	condition:
		$a0 at pe.entry_point
}