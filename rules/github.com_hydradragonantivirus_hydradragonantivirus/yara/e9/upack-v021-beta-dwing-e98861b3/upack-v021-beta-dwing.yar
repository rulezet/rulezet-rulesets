import "pe"
rule _Upack_v021_Beta__Dwing_
{
	meta:
		description = "Upack v0.21 Beta -> Dwing"
	strings:
		$0 = {BE 88 01 ?? ?? AD 8B F8 ?? ?? ?? ?? 33}
	condition:
		$0 at pe.entry_point
}