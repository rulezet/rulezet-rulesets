import "pe"
rule _PPCPROTECT_10__Alexey_Gorchakov_
{
	meta:
		description = "PPC-PROTECT 1.0 -> Alexey Gorchakov"
	strings:
		$0 = {FF 5F 2D E9}
	condition:
		$0 at pe.entry_point
}