import "pe"
rule _ASProtect_11_MTE__Solodovnikov_Alexey_
{
	meta:
		description = "ASProtect 1.1 MTE -> Solodovnikov Alexey"
	strings:
		$0 = {60 E9 ?? ?? ?? ?? 91 78 79 79 79 E9}
	condition:
		$0 at pe.entry_point
}