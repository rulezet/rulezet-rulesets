import "pe"
rule _PECompact_09784_
{
	meta:
		description = "PECompact 0.978.4"
	strings:
		$0 = {EB 06 68 00 00 00 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB D1 84 40 00 87 DD 8B 85 56 85 40 00 01 85 C5 84 40 00 66 C7 85 C2 84 40 00 90 90 BB A6 09 00 00 03 9D 5A 85 40 00 03 9D 56 85 40 00 53 53 53 58 2D 2C}
	condition:
		$0 at pe.entry_point
}