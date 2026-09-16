import "pe"
rule _PseudoSigner_01_Borland_Delphi_50_KOLMCK__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Borland Delphi 5.0 KOL/MCK] --> Anorganix"
	strings:
		$0 = {55 8B EC 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 FF 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 EB 04 00 00 00 01 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90}
	condition:
		$0 at pe.entry_point
}