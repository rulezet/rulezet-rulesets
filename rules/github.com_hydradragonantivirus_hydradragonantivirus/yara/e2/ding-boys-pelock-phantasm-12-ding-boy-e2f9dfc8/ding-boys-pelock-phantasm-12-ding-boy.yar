import "pe"
rule _Ding_Boys_PElock_Phantasm_12__Ding_Boy_
{
	meta:
		description = "Ding Boy's PE-lock Phantasm 1.2 -> Ding Boy"
	strings:
		$0 = {55 57 56 52 51 53 9C FA 90 E8 00 00 00 00 5D 8B D5}
	condition:
		$0 at pe.entry_point
}