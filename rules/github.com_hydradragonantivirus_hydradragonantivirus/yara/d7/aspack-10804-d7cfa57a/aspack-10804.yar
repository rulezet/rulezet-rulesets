rule aspack_10804
{
	meta:
		author = "PEiD"
		description = "ASPack 1.08.04 -> Alexey Solodovnikov"
		group = "105"
		function = "0"
	strings:
		$a0 = { 60 E8 41 06 ?? ?? EB 41 }
	condition:
		$a0
}