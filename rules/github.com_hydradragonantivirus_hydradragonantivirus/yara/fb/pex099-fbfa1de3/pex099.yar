import "pe"
rule pex099
{
	meta:
		author = "PEiD"
		description = "PEX 0.99 -> bart/CrackPl"
		group = "160"
		function = "0"
	strings:
		$a0 = { 60 E8 01 ?? ?? ?? ?? 83 C4 04 E8 01 ?? ?? ?? ?? 5D 81 }
	condition:
		$a0 at pe.entry_point
}