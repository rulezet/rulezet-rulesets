import "pe"
rule _Armadillo_25x__26x__Silicon_Realms_Toolworks_
{
	meta:
		description = "Armadillo 2.5x - 2.6x -> Silicon Realms Toolworks"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 58 ?? ?? ?? 33 D2 8A D4 89 15 EC}
	condition:
		$0 at pe.entry_point
}