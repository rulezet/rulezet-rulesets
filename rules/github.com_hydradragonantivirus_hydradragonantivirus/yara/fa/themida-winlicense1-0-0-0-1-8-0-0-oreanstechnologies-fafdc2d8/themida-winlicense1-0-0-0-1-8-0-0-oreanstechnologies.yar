rule Themida_WinLicense1_0_0_0_1_8_0_0__OreansTechnologies
{
	meta:
		author = "PEiD"
		description = "Themida/WinLicense 1.0.0.0-1.8.0.0-> Oreans Technologies"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? E8 00 00 00 00 }
	condition:
		$a0
}