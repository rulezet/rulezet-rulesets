import "pe"
rule _PseudoSigner_02_Macromedia_Flash_Projector_60__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [Macromedia Flash Projector 6.0] --> Anorganix"
	strings:
		$0 = {90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 83 EC 44 56 FF 15 24 81 49 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C}
	condition:
		$0 at pe.entry_point
}