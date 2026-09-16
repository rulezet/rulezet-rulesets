import "pe"
rule _Visual_Cpp_50_
{
	meta:
		description = "Visual C++ 5.0"
	strings:
		$0 = {55 8B EC 6A FF 68 00 00 00 00 68 00 00 00 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 C4 00 53 56 57 89 65 E8 FF 15}
	condition:
		$0 at pe.entry_point
}