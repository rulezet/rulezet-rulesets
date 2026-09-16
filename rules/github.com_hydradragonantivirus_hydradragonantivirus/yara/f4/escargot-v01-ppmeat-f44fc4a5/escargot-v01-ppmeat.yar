import "pe"
rule _Escargot_V01__ppMeat_
{
	meta:
		description = "Escargot V0.1 -> ++Meat"
	strings:
		$0 = {EB 04 40 30 2E 31 60 68 61}
	condition:
		$0 at pe.entry_point
}