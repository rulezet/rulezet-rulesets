import "pe"
rule _PseudoSigner_01_PENinja_131_
{
	meta:
		description = "PseudoSigner 0.1 [PENinja 1.31"
	strings:
		$0 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 E9}
		$1 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 E9}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}