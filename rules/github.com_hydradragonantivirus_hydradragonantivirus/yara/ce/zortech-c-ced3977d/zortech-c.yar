import "pe"
rule _Zortech_C_
{
	meta:
		description = "Zortech C"
	strings:
		$0 = {FA FC B8 ?? ?? ?? 8C C8 8E D8}
		$1 = {E8 ?? ?? 2E FF ?? ?? ?? FC 06}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}