import "pe"
rule _TurboChainer_103_
{
	meta:
		description = "TurboChainer 1.03"
	strings:
		$0 = {BA 24 00 8E DA 8C D3 2B DA D1 E3 D1 E3 D1 E3 D1 E3 FA 8E D2 03 E3 FB B8 24 00 8E D8 1E FC 8D 06 B0 00 83 C0 0C 50 1E BE 80 00 8C C0 8E D8 07 5F 8B 0C 32 ED 51 46 F3 A4 59 1F 00 0E AF 00 1E B4 51 32 C0 CD 21 8E DB BB 2C 00 8B 07 8E D8 33 DB}
	condition:
		$0 at pe.entry_point
}