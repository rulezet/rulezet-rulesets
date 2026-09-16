import "pe"
rule _AHPack_V01__FEUERRADER_
{
	meta:
		description = "AHPack V0.1 -> FEUERRADER"
	strings:
		$0 = {60 68 54 ?? ?? 00 B8 48 ?? ?? 00 FF 10 68 B3 ?? ?? 00 50 B8 44 ?? ?? 00 FF 10 68 00}
	condition:
		$0 at pe.entry_point
}