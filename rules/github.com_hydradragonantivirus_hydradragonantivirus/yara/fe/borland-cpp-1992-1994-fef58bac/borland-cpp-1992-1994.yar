import "pe"
rule _Borland_Cpp_1992_1994_
{
	meta:
		description = "Borland C++ 1992, 1994"
	strings:
		$0 = {8C C8 8E D8 8C 1E ?? ?? 8C 06 ?? ?? 8C 06 ?? ?? 8C 06}
	condition:
		$0 at pe.entry_point
}