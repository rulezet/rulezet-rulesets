import "pe"
rule _FreeJoiner_Small_build_023__GlOFF_
{
	meta:
		description = "FreeJoiner Small (build 023) -> GlOFF"
	strings:
		$0 = {E8 E1 FD FF FF 6A 00 E8 0C 00 00 00 FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00}
	condition:
		$0 at pe.entry_point
}