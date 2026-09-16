import "pe"
rule _Upack_V03X__Dwing_
{
	meta:
		description = "Upack V0.3X -> Dwing"
	strings:
		$0 = {60 E8 09 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C9 5E 87 0E}
	condition:
		$0 at pe.entry_point
}