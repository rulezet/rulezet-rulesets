import "pe"
rule _ASPR_Stripper_v2x_unpacked_
{
	meta:
		description = "ASPR Stripper v2.x unpacked"
	strings:
		$0 = {55 8B EC 81 C4 E4 FE FF FF 53 56 57 33 C0 89 45 F0 89}
	condition:
		$0 at pe.entry_point
}