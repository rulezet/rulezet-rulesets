import "pe"
rule _PseudoSigner_02_32Lite_003_
{
	meta:
		description = "PseudoSigner 0.2 [32Lite 0.03"
	strings:
		$0 = {60 06 FC 1E 07 BE 90 90 90 90 6A 04 68 90 10 90 90 68}
		$1 = {60 06 FC 1E 07 BE 90 90 90 90 6A 04 68 90 10 90 90 68}
		$2 = {60 06 FC 1E 07 BE 90 90 90 90 6A 04 68 90 10 90 90 68}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point or $2 at pe.entry_point
}