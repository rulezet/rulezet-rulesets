import "pe"
rule _tElock_v095__tHE_EGOiSTE_
{
	meta:
		description = "tElock v0.95 -> tHE EGOiSTE"
	strings:
		$0 = {E9 D5 E4 FF FF 00}
	condition:
		$0 at pe.entry_point
}