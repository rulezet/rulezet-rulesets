import "pe"
rule _tElock_v100__tHE_EGOiSTE_
{
	meta:
		description = "tElock v1.00 -> tHE EGOiSTE"
	strings:
		$0 = {E9 E5 E2 FF FF}
	condition:
		$0 at pe.entry_point
}