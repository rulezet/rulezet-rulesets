import "pe"
rule _ASPack_102b__Solodovnikov_Alexey_
{
	meta:
		description = "ASPack 1.02b -> Solodovnikov Alexey"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED 96 78 43 00 B8 90 78 43 00 03 C5 2B 85 7D 7C 43 00 89 85 89 7C 43 00 80 BD 74 7C 43}
	condition:
		$0 at pe.entry_point
}