import "pe"
rule _PseudoSigner_01_CrunchPE_Heuristic_
{
	meta:
		description = "PseudoSigner 0.1 [Crunch/PE Heuristic"
	strings:
		$0 = {55 E8 0E 00 00 00 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 00 00 00 00 E9}
		$1 = {55 E8 0E 00 00 00 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 00 00 00 00 E9}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}