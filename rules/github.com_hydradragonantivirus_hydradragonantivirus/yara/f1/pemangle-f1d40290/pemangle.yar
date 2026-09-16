import "pe"
rule _PEMangle_
{
	meta:
		description = "PEMangle"
	strings:
		$0 = {E8 B9 1B 01}
	condition:
		$0 at pe.entry_point
}