import "pe"
rule aspack_heur
{
	meta:
		author = "PEiD"
		description = "ASPack 2.x (without poly) -> Alexey Solodovnikov"
		group = "105"
		function = "0"
	strings:
		$a0 = { 59 0B C9 89 85 ?? ?? ?? ?? 61 75 08 B8 01 ?? ?? ?? C2 0C ?? 68 ?? ?? ?? ?? C3 }
	condition:
		$a0 at pe.entry_point
}