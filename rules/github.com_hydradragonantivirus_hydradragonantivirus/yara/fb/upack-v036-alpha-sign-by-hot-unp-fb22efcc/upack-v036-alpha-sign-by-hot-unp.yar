rule _Upack_v036_alpha__Sign_by_hot_UNP_
{
	meta:
		description = "Upack v0.36 alpha -> Sign by hot_UNP"
	strings:
		$0 = {AB E2 E5 5D 59 8B 76 68 51 59 46 AD 85 C0}
	condition:
		$0
}