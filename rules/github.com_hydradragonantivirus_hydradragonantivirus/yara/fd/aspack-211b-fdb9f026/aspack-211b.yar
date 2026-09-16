import "pe"
rule aspack_211b
{
	meta:
		author = "PEiD"
		description = "ASPack 2.11b -> Alexey Solodovnikov"
		group = "100"
		function = "0"
	strings:
		$a0 = { 60 E8 02 ?? ?? ?? EB 09 5D 55 81 ED 39 39 44 ?? C3 E9 3D 04 }
	condition:
		$a0 at pe.entry_point
}