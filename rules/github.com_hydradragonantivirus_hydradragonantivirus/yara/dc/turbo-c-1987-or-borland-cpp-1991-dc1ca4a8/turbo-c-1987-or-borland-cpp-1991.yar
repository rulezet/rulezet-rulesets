import "pe"
rule _Turbo_C_1987_or_Borland_Cpp_1991_
{
	meta:
		description = "Turbo C 1987 or Borland C++ 1991"
	strings:
		$0 = {FB BA ?? ?? 2E 89 ?? ?? ?? B4 30 CD 21}
	condition:
		$0 at pe.entry_point
}