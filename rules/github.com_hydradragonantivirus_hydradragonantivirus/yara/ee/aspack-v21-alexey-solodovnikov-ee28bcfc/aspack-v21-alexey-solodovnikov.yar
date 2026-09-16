import "pe"
rule _ASPack_v21__Alexey_Solodovnikov_
{
	meta:
		description = "ASPack v2.1 -> Alexey Solodovnikov"
	strings:
		$0 = {60 E8 72 05 00 00 EB 33 87 DB 90 00}
	condition:
		$0 at pe.entry_point
}