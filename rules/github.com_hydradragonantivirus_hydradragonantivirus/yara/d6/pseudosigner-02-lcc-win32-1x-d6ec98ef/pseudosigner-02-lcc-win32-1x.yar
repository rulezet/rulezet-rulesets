import "pe"
rule _PseudoSigner_02_LCC_Win32_1x_
{
	meta:
		description = "PseudoSigner 0.2 [LCC Win32 1.x"
	strings:
		$0 = {64 A1 01 00 00 00 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 90 50}
	condition:
		$0 at pe.entry_point
}