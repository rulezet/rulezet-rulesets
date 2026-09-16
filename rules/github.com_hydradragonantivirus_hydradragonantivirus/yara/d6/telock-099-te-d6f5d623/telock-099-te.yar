import "pe"
rule _tElock_099__tE_
{
	meta:
		description = "tElock 0.99 -> tE!"
	strings:
		$0 = {E9 5E DF FF FF 00 00 00 ?? ?? ?? ?? E5 ?? ?? 00 00 00 00 00 00 00 00 00 05}
	condition:
		$0 at pe.entry_point
}