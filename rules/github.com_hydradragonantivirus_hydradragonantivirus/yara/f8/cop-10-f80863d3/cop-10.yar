import "pe"
rule _COP_10_
{
	meta:
		description = "COP 1.0"
	strings:
		$0 = {BF E8 00 BE 1C 01 B9 18 00 AC 32 06 09 01 AA E2 F8 8B 16 18 01 EB D1 90 68 00 00 00 12 98 AD 3C 13 AC AD 3C 27 A2 B6 AD 7D 45 27 BA B4 AD 01 9D 7C 07 4E 56}
	condition:
		$0 at pe.entry_point
}