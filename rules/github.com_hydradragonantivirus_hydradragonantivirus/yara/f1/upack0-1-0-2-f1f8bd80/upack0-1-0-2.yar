rule Upack0_1_0_2
{
	meta:
		author = "PEiD"
		description = "Upack 0.1x - 0.2x -> Dwing"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { BE 88 01 ?? ?? AD 8B F8 95 }
	condition:
		$a0
}