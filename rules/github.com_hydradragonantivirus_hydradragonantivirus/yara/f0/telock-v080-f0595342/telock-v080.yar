import "pe"
rule _tElock_v080_
{
	meta:
		description = "tElock v0.80"
	strings:
		$0 = {60 E8 ?? ?? C3}
	condition:
		$0 at pe.entry_point
}