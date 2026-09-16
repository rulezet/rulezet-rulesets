import "pe"
rule _MSLRH_032a_fake_MSVCpp_DLL_Method_4__emadicius_
{
	meta:
		description = "MSLRH 0.32a (fake MSVC++ DLL Method 4) -> emadicius"
	strings:
		$0 = {55 8B EC 56 57 BF 01 00 00 00 8B 75 0C 85 F6 5F 5E 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75}
	condition:
		$0 at pe.entry_point
}