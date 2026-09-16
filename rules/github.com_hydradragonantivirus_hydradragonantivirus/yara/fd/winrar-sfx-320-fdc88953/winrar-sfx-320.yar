rule winrar_sfx_320
{
	meta:
		author = "PEiD"
		description = "WinRAR 32-bit SFX 3.20 module"
		group = "444"
		function = "0"
	strings:
		$a0 = { E9 D3 18 00 00 00 00 00 00 90 90 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 DD 30 41 00 6A 00 6A 00 8B C6 8B CF E8 32 42 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF 75 14 6A 66 56 E8 C8 19 01 00 B8 01 00 00 00 EB 47 66 81 E7 FF FF 66 FF CF 74 07 66 FF CF 74 23 EB 30 68 80 00 00 00 68 98 40 41 00 6A 65 56 E8 }
	condition:
		$a0
}