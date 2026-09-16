import "pe"
rule _Borland_Delphi_3_2_
{
	meta:
		description = "Borland Delphi 3 (2)"
	strings:
		$0 = {55 8B EC 83 C4 F0 53 56 57 33 C0 89 45 F0 E8 00 00 FF FF E8 00 00 FF FF 33 C0 55 68 00 00 40 00 64 FF 30 64 89 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 F0 33 C0 E8 00 00 FF FF 8B 45 F0 E8 00 00 FF FF 50 E8 00 00 FF FF}
	condition:
		$0 at pe.entry_point
}