rule armd84
{
	meta:
		author = "PEiD"
		description = "Armadillo 1.84 -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 55 8B EC 6A FF 68 E8 C1 ?? ?? 68 F4 86 ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 }
	condition:
		$a0
}