import "pe"
rule _Microsoft_Visual_Cpp__
{
	meta:
		description = "Microsoft Visual C++ ?.?"
	strings:
		$0 = {83 ?? ?? 6A 00 FF 15 F8 10 0B B0 8D ?? ?? ?? 51 6A 08 6A 00 6A 00 68}
	condition:
		$0 at pe.entry_point
}