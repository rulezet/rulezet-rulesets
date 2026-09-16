import "pe"
rule _FreeJoiner_153_Stub_engine_171__GlOFF_
{
	meta:
		description = "FreeJoiner 1.5.3 (Stub engine 1.7.1) -> GlOFF"
	strings:
		$0 = {E8 02 FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A8 10 40 00}
	condition:
		$0 at pe.entry_point
}