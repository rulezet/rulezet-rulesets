import "pe"
rule _ASProtect_12__Solodovnikov_Alexey_
{
	meta:
		description = "ASProtect 1.2 -> Solodovnikov Alexey"
	strings:
		$0 = {68 01 ?? ?? ?? C3}
	condition:
		$0 at pe.entry_point
}