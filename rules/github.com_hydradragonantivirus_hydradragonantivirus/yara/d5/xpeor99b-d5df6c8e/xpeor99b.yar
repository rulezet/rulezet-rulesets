import "pe"
rule xpeor99b
{
	meta:
		author = "PEiD"
		description = "X-PEOR 0.99b -> MadMax"
		group = "193"
		function = "0"
	strings:
		$a0 = { E8 ?? ?? ?? ?? 5D 8B CD 81 ED 7A 29 40 ?? 89 AD 0F 6D 40 }
	condition:
		$a0 at pe.entry_point
}