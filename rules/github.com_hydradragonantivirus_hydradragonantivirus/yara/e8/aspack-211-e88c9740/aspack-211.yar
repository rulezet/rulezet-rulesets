rule aspack_211
{
	meta:
		author = "PEiD"
		description = "ASPack 2.11 -> Alexey Solodovnikov"
		group = "100"
		function = "0"
	strings:
		$a0 = { 60 E9 3D 04 }
	condition:
		$a0
}