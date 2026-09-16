import "pe"
rule _pex_V099__params_
{
	meta:
		description = "pex V0.99 -> params"
	strings:
		$0 = {E9 F5 00 00 00}
	condition:
		$0 at pe.entry_point
}