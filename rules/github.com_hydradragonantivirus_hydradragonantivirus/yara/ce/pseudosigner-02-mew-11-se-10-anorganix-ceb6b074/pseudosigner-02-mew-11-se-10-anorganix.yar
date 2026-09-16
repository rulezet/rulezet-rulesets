import "pe"
rule _PseudoSigner_02_MEW_11_SE_10__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [MEW 11 SE 1.0] --> Anorganix"
	strings:
		$0 = {E9 09 00 00 00 00 00 00 02 00 00 00 0C 90}
	condition:
		$0 at pe.entry_point
}