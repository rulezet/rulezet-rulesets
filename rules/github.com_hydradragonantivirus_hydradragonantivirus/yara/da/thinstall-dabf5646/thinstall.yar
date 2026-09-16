rule thinstall
{
	meta:
		author = "PEiD"
		description = "Thinstall 2.x -> Jitit Inc"
		group = "181"
		function = "0"
	strings:
		$a0 = { B8 EF BE AD DE 50 6A 00 FF 15 ?? ?? ?? 00 E9 ?? FF FF FF }
	condition:
		$a0
}