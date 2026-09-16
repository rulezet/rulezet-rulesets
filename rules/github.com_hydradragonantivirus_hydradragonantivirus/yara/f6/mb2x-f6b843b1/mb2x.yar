rule mb2x
{
	meta:
		author = "PEiD"
		description = "MoleBox 2.x.x -> Mole Studio"
		group = "198"
		function = "0"
	strings:
		$a0 = { 60 E8 4F 00 00 00 }
	condition:
		$a0
}