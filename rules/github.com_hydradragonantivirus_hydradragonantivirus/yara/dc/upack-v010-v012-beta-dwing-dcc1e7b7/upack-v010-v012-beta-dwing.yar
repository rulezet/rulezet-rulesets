import "pe"
rule _Upack_v010__v012_Beta__Dwing_
{
	meta:
		description = "Upack v0.10 - v0.12 Beta -> Dwing"
	strings:
		$0 = {BE 48 01 ?? ?? ?? ?? ?? 95 A5 33 C0}
	condition:
		$0 at pe.entry_point
}