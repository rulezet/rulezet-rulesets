import "pe"
rule _MSLRH_032a_fake_Microsoft_Visual_Cpp__emadicius_
{
	meta:
		description = "MSLRH 0.32a (fake Microsoft Visual C++) -> emadicius"
	strings:
		$0 = {55 8B EC 6A FF 68 CA 37 41 00 68 06 38 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 64 8F 05 00 00 00 00 83 C4 0C 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00}
	condition:
		$0 at pe.entry_point
}