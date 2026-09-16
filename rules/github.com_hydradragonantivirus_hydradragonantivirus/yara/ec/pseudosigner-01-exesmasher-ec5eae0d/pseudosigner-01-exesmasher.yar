import "pe"
rule _PseudoSigner_01_ExeSmasher_
{
	meta:
		description = "PseudoSigner 0.1 [ExeSmasher"
	strings:
		$0 = {9C FE 03 90 60 BE 90 90 41 90 8D BE 90 10 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 FE 0B E9}
		$1 = {9C FE 03 90 60 BE 90 90 41 90 8D BE 90 10 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 FE 0B E9}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}