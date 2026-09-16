rule gm12
{
	meta:
		author = "PEiD"
		description = "Goat's PE Mutilator 1.2"
		group = "124"
		function = "0"
	strings:
		$a0 = { E8 E9 0B 00 00 00 00 00 }
	condition:
		$a0
}