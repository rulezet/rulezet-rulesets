import "pe"
rule _ASProtect_11_BRS__Solodovnikov_Alexey_
{
	meta:
		description = "ASProtect 1.1 BRS -> Solodovnikov Alexey"
	strings:
		$0 = {60 E9 ?? 05 00 00}
	condition:
		$0 at pe.entry_point
}