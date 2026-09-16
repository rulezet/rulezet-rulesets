import "pe"
rule _PseudoSigner_02_Gleam_100_
{
	meta:
		description = "PseudoSigner 0.2 [Gleam 1.00"
	strings:
		$0 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 0C 53 56 57 E8 24 02 00 FF}
	condition:
		$0 at pe.entry_point
}