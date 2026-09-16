import "pe"
rule _PseudoSigner_01_Microsoft_Visual_Basic_60_DLL__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Microsoft Visual Basic 6.0 DLL] --> Anorganix"
	strings:
		$0 = {90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 5A 68 90 90 90 90 68 90 90 90 90 52 E9 90 90 FF}
	condition:
		$0 at pe.entry_point
}