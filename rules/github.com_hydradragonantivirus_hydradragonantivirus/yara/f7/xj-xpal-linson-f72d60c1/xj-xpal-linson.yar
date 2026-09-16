import "pe"
rule _XJ__XPAL__LiNSoN_
{
	meta:
		description = "XJ / XPAL -> LiNSoN"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? ?? 40 00 68 ?? ?? 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 44 53 56 57 66 9C}
	condition:
		$0 at pe.entry_point
}