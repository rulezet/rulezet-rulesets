import "pe"
rule _PseudoSigner_02_REALBasic__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [REALBasic] --> Anorganix"
	strings:
		$0 = {55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01}
	condition:
		$0 at pe.entry_point
}