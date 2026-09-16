import "pe"
rule _ShellModify_01__pll621_
{
	meta:
		description = "ShellModify 0.1 -> pll621"
	strings:
		$0 = {55 8B EC 6A FF 68 98 66 41 00 68 3C 3D 41 00 64 A1 00 00 00 00}
	condition:
		$0 at pe.entry_point
}