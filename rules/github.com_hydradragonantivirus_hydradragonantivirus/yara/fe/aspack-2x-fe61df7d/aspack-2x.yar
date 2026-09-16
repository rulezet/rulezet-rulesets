import "pe"
rule aspack_2x
{
	meta:
		author = "PEiD"
		description = "ASPack 2.xx Heuristic Mode -> Alexey Solodovnikov"
		group = "105"
		function = "0"
	strings:
		$a0 = { A8 03 ?? ?? 61 75 08 B8 01 ?? ?? ?? C2 0C ?? 68 ?? ?? ?? ?? C3 8B 85 26 04 ?? ?? 8D 8D 3B 04 ?? ?? 51 50 FF 95 }
	condition:
		$a0 at pe.entry_point
}