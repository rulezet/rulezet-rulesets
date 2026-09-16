import "pe"
rule _FSG_v110_Eng__dulekxt__Borland_Cpp_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Borland C++)"
	strings:
		$0 = {23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB}
		$1 = {23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB F4 00 00 00 EB 02 04 FA EB 01 FA EB 01 5F EB 02 CD 20 8A 16 EB 02 11 31 80 E9 31 EB 02 30 11 C1 E9 11 80 EA 04 EB 02 F0 EA 33 CB 81 EA AB AB 19 08 04 D5 03 C2 80 EA}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}