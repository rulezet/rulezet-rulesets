import "pe"
rule _PseudoSigner_01_CDCops_II_
{
	meta:
		description = "PseudoSigner 0.1 [CD-Cops II"
	strings:
		$0 = {53 60 BD 90 90 90 90 8D 45 90 8D 5D 90 E8 00 00 00 00 8D 01 E9}
		$1 = {53 60 BD 90 90 90 90 8D 45 90 8D 5D 90 E8 00 00 00 00 8D 01 E9}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}