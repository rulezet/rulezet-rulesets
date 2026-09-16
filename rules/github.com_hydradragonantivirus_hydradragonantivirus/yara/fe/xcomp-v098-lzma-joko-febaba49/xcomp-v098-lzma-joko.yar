import "pe"
rule _XComp_V098_LZMA__JoKo_
{
	meta:
		description = "XComp V0.98 (LZMA) -> JoKo"
	strings:
		$0 = {68 ?? ?? ?? 00 9C 60 E8 75 06 00 00 34 ?? ?? 00 00 00 00 00 00 00 00 00 4C ?? ?? 00 34 ?? ?? 00 00 00 00}
	condition:
		$0 at pe.entry_point
}