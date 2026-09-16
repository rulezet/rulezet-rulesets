rule mb2x_BoB
{
	meta:
		author = "PEiD"
		description = "MoleBox 2.x.x -> Mole Studio"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { E8 00 00 00 00 60 E8 4F 00 00 00 }
	condition:
		$a0
}