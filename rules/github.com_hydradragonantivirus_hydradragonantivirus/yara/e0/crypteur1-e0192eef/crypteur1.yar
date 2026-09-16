import "pe"
rule crypteur1
{
	meta:
		author = "PEiD"
		description = "Crypteur 1.00 -> Morgatte"
		group = "110"
		function = "0"
	strings:
		$a0 = { 68 ?? ?? ?? ?? 5F 68 ?? ?? ?? ?? 58 33 DB EB 0D 8A 14 03 80 EA 07 80 F2 04 88 14 03 43 81 FB ?? ?? ?? ?? 72 EB 68 ?? ?? ?? ?? 5E FF E6 }
	condition:
		$a0 at pe.entry_point
}