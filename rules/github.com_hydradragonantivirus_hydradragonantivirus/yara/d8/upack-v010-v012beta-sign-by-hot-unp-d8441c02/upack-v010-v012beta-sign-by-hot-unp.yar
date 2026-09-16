import "pe"
rule _Upack_v010__v012Beta__Sign_by_hot_UNP_
{
	meta:
		description = "Upack v0.10 - v0.12Beta -> Sign by hot_UNP"
	strings:
		$0 = {BE 48 01 ?? ?? ?? ?? ?? 95 A5 33 C0}
	condition:
		$0 at pe.entry_point
}