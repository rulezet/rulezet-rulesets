import "pe"
rule _Cexe_10a_
{
	meta:
		description = "Cexe 1.0a"
	strings:
		$0 = {55 8B EC 81 EC 0C 02 00 00 56 BE 04 01 00 00 8D 85 F8 FE FF FF 56 50 6A 00 FF 15 54 10 40 00 8A 8D F8 FE FF FF 33 D2 84 C9 8D 85 F8 FE FF FF 74 16 80 F9 5C 75 03 8D 50 01 8A 48 01 40 84 C9 75 F0 85 D2 74 02 20 0A 8D 45 FC 50 8D 85 F8 FE FF}
	condition:
		$0 at pe.entry_point
}