import "pe"
rule _Microsoft_Visual_Cpp_42_DLL_
{
	meta:
		description = "Microsoft Visual C++ 4.2 (DLL)"
	strings:
		$0 = {53 B8 ?? ?? ?? ?? 8B ?? ?? ?? 56 57 85 DB 55 75}
	condition:
		$0 at pe.entry_point
}