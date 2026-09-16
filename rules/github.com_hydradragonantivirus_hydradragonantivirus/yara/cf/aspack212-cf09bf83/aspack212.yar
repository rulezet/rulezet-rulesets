rule ASPack212
{
	meta:
		author = "PEiD"
		description = "ASPack 2.12 -> Alexey Solodovnikov"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB }
	condition:
		$a0
}