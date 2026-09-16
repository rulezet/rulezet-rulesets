import "pe"
rule _Microsoft_Visual_Cpp_50_
{
	meta:
		description = "Microsoft Visual C++ 5.0"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50}
	condition:
		$0 at pe.entry_point
}