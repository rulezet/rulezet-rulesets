rule armd253b3
{
	meta:
		author = "PEiD"
		description = "Armadillo 2.53 beta3 -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 55 8B EC 6A FF 68 D8 ?? ?? ?? 68 14 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 }
	condition:
		$a0
}