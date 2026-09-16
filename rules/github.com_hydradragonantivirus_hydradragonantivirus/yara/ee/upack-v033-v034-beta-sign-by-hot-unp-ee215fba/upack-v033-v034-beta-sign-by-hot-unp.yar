import "pe"
rule _Upack_v033__v034_Beta__Sign_by_hot_UNP_
{
	meta:
		description = "Upack v0.33 ~ v0.34 Beta -> Sign by hot_UNP"
	strings:
		$0 = {59 F3 A5 83 C8 FF 8B DF AB 40 AB 40}
	condition:
		$0 at pe.entry_point
}