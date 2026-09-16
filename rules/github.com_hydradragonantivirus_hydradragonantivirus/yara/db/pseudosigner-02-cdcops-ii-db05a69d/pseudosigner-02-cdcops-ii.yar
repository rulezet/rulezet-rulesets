import "pe"
rule _PseudoSigner_02_CDCops_II_
{
	meta:
		description = "PseudoSigner 0.2 [CD-Cops II"
	strings:
		$0 = {53 60 BD 90 90 90 90 8D 45 90 8D 5D 90 E8 00 00 00 00 8D 01}
	condition:
		$0 at pe.entry_point
}