import "pe"
rule _FSG_v110_Eng__dulekxt__Borland_Delphi_20_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Borland Delphi 2.0)"
	strings:
		$0 = {EB 01 56 E8 02 00 00 00 B2 D9 59 68 80 ?? 41 00 E8 02 00 00 00 65 32 59 5E EB 02 CD 20 BB}
	condition:
		$0 at pe.entry_point
}