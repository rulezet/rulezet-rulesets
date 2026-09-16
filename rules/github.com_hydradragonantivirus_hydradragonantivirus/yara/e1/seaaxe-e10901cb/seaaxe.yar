import "pe"
rule _SEAAXE_
{
	meta:
		description = "SEA-AXE"
	strings:
		$0 = {FC BC ?? ?? 0E 1F E8 ?? ?? 26 A1 ?? ?? 8B 1E ?? ?? 2B C3 8E C0 B1 ?? D3 E3}
	condition:
		$0 at pe.entry_point
}