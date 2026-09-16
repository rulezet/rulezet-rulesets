import "pe"
rule _tElock_v090__tHE_EGOiSTE_
{
	meta:
		description = "tElock v0.90 -> tHE EGOiSTE"
	strings:
		$0 = {E8 02 00 00 00 E8 00 E8 00 00 00 00 5E 2B}
	condition:
		$0 at pe.entry_point
}