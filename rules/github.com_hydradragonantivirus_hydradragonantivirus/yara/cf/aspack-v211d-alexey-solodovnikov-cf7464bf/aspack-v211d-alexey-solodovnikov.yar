import "pe"
rule _ASPack_v211d__Alexey_Solodovnikov_
{
	meta:
		description = "ASPack v2.11d -> Alexey Solodovnikov"
	strings:
		$0 = {60 E8 02 00 00 00 EB 09 5D 55}
	condition:
		$0 at pe.entry_point
}