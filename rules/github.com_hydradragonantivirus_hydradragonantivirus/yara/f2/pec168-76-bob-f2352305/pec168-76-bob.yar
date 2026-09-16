rule pec168_76_BoB
{
	meta:
		author = "PEiD"
		description = "PECompact 1.68 - 1.84 -> Jeremy Collake"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 ?? 87 DD 8B 85 E6 90 40 ?? 01 85 33 90 40 ?? 66 C7 85 ?? 90 40 ?? 90 90 01 85 DA 90 40 ?? 01 85 DE 90 40 ?? 01 85 E2 90 40 ?? BB 7B 11 }
	condition:
		$a0
}