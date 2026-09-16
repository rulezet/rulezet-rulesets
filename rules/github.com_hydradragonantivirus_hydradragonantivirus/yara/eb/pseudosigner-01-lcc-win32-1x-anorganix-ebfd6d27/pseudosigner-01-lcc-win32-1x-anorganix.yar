import "pe"
rule _PseudoSigner_01_LCC_Win32_1x__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [LCC Win32 1.x] --> Anorganix"
	strings:
		$0 = {64 A1 01 00 00 00 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 90 50 E9}
	condition:
		$0 at pe.entry_point
}