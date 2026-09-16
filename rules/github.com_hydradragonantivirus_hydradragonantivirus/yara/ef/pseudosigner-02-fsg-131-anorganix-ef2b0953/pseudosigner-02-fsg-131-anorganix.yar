import "pe"
rule _PseudoSigner_02_FSG_131__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [FSG 1.31] --> Anorganix"
	strings:
		$0 = {BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80}
	condition:
		$0 at pe.entry_point
}