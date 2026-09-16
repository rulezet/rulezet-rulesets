import "pe"
rule _Upack_Patch_or_any_Version__Dwing_
{
	meta:
		description = "Upack_Patch or any Version -> Dwing"
	strings:
		$0 = {60 E8 09 00 00 00 ?? ?? ?? 00 E9 06 02}
	condition:
		$0 at pe.entry_point
}