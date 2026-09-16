import "pe"
rule _Ding_Boys_PElock_v007_
{
	meta:
		description = "Ding Boy's PE-lock v0.07"
	strings:
		$0 = {55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 ED 0D 39}
	condition:
		$0 at pe.entry_point
}