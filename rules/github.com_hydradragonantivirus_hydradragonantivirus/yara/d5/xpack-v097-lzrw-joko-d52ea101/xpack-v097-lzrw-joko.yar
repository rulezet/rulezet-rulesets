import "pe"
rule _XPack_V097_LZRW__JoKo_
{
	meta:
		description = "XPack V0.97 (LZRW) -> JoKo"
	strings:
		$0 = {68 ?? ?? ?? 00 9C 60 E8 4D 02 00 00 34 ?? ?? 00 00 00 00 00 00 00 00 00 44 ?? ?? 00 34 ?? ?? 00 00 00}
	condition:
		$0 at pe.entry_point
}