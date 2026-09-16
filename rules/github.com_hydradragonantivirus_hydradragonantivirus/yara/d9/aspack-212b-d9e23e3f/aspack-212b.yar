rule aspack_212b
{
	meta:
		author = "PEiD"
		description = "ASPack 2.12b -> Alexey Solodovnikov"
		group = "100"
		function = "6"
	strings:
		$a0 = { 90 60 E8 03 ?? ?? ?? E9 EB 04 5D 45 55 C3 E8 01 ?? ?? ?? EB 5D BB EC FF FF FF 03 DD 81 EB }
	condition:
		$a0
}