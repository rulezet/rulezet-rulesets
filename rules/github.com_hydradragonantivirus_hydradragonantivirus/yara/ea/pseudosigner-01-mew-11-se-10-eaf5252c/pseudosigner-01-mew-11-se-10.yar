import "pe"
rule _PseudoSigner_01_MEW_11_SE_10_
{
	meta:
		description = "PseudoSigner 0.1 [MEW 11 SE 1.0"
	strings:
		$0 = {E9 09 00 00 00 00 00 00 02 00 00 00 0C 90 E9}
		$1 = {E9 09 00 00 00 00 00 00 02 00 00 00 0C 90 E9}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}