import "pe"
rule pec099
{
	meta:
		author = "PEiD"
		description = "PECompact 0.99 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 2F 85 40 ?? 87 DD 8B 85 B4 85 }
	condition:
		$a0 at pe.entry_point
}