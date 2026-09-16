import "pe"
rule _ThemidaWinLicense_V2100_p__Oreans_Technologies__20090917_
{
	meta:
		description = "Themida/WinLicense V2.1.0.0 + -> Oreans Technologies * 20090917"
	strings:
		$0 = {83 EC 04 50 53 E8 ?? ?? 00 00 CC 58 8B D8 40 2D ?? ?? ?? ?? 2D ?? ?? ?? ?? 05 ?? ?? ?? ?? 80 3B CC 75 19 C6 03 00 BB 00 10 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 50 E8 0A 00 00 00 83 C0 00 89 44 24 08 5B 58 C3 55 8B EC 60 8B 75 08 8B 4D 0C C1 E9 02 8B 45 10 8B 5D 14 EB 08 31 06 01 1E 83 C6 04 49 0B C9 75 F4 61 C9 C2 10 00}
	condition:
		$0 at pe.entry_point
}