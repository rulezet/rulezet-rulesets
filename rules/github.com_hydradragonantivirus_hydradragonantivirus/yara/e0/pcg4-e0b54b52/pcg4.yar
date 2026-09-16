import "pe"
rule pcg4
{
	meta:
		author = "PEiD"
		description = "PC-Guard 4.03 - 4.15 -> Blagoje Ceklic"
		group = "135"
		function = "0"
	strings:
		$a0 = { FC 55 50 E8 ?? ?? ?? ?? 5D EB 01 E3 60 E8 03 ?? ?? ?? D2 EB 0B 58 EB 01 48 40 EB 01 }
	condition:
		$a0 at pe.entry_point
}