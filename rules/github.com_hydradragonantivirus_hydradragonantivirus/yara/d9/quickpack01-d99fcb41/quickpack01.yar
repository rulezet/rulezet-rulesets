rule QuickPack01
{
	meta:
		author = "PEiD"
		description = "QuickPack NT 0.1 -> ?"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { 4D 5A 90 EB 01 00 52 E9 62 01 00 00 50 45 00 00 4C 01 01 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 00 40 00 00 10 00 }
	condition:
		$a0
}