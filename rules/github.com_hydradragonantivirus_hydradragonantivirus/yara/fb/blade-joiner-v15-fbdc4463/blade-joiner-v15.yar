import "pe"
rule _Blade_Joiner_v15_
{
	meta:
		description = "Blade Joiner v1.5"
	strings:
		$0 = {60 BD}
	condition:
		$0 at pe.entry_point
}