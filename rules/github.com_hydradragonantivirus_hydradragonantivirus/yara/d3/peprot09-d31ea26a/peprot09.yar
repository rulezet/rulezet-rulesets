rule peprot09
{
	meta:
		author = "PEiD"
		description = "PE Protect 0.9 -> Christoph Gabler"
		group = "156"
		function = "0"
	strings:
		$a0 = { 52 51 55 57 64 67 A1 30 ?? 85 C0 78 0D E8 ?? ?? ?? ?? 58 83 C0 07 C6 ?? C3 }
	condition:
		$a0
}