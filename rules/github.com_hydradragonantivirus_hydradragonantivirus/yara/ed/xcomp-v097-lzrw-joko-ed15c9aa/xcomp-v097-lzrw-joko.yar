import "pe"
rule _XComp_V097_LZRW__JoKo_
{
	meta:
		description = "XComp V0.97 (LZRW) -> JoKo"
	strings:
		$0 = {68 ?? ?? ?? 00 9C 60 E8 9B 02 00 00 34 ?? ?? 00 00 00 00 00 00 00 00 00 4C ?? ?? ?? 34 ?? ?? 00 00 00 00 00 00 00}
	condition:
		$0 at pe.entry_point
}