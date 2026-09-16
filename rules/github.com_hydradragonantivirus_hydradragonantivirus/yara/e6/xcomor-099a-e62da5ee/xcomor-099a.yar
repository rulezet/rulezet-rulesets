import "pe"
rule _XcomOR_099a_
{
	meta:
		description = "XcomOR 0.99a"
	strings:
		$0 = {80 06 01 01 0A B4 01 50 50 C3 BF 00 01 57 B8 00 00 8B 4D 01 8B 5D 03 33 D8 89 1D 83 C7 02 05 87 00 83 F9 01 74 01 49 E2 EB 58 FF E0}
	condition:
		$0 at pe.entry_point
}