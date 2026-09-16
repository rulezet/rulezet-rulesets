import "pe"
rule _PseudoSigner_01_Gleam_100_
{
	meta:
		description = "PseudoSigner 0.1 [Gleam 1.00"
	strings:
		$0 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 0C 53 56 57 E8 24 02 00 FF E9}
		$1 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 0C 53 56 57 E8 24 02 00 FF E9}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}