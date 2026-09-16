import "pe"
rule _ASProtect_v12x_
{
	meta:
		description = "ASProtect v1.2x"
	strings:
		$0 = {68 01 ?? E8 01 ?? ?? ?? C3}
	condition:
		$0 at pe.entry_point
}