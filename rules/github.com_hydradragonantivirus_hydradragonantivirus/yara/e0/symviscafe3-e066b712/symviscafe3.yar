import "pe"
rule symviscafe3
{
	meta:
		author = "PEiD"
		description = "Symantec Visual Cafe 3.0"
		group = "28"
		function = "0"
	strings:
		$a0 = { 64 8B 05 ?? ?? ?? ?? 55 8B EC 6A FF 68 ?? ?? 40 ?? 68 ?? ?? 40 ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 08 50 53 56 57 89 65 E8 C7 45 FC }
	condition:
		$a0 at pe.entry_point
}