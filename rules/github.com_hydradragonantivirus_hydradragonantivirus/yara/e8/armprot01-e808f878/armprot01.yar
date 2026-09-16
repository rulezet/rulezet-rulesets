import "pe"
rule armprot01
{
	meta:
		author = "PEiD"
		description = "ARM Protector 0.1 -> SMoKE"
		group = "100"
		function = "0"
	strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 5E 1F 40 00 EB 02 }
	condition:
		$a0 at pe.entry_point
}