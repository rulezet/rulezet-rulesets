import "pe"
rule _FSG_v110_Eng__dulekxt__Borland_Delphi__Microsoft_Visual_Cppx_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Borland Delphi / Microsoft Visual C++)x"
	strings:
		$0 = {1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00}
	condition:
		$0 at pe.entry_point
}