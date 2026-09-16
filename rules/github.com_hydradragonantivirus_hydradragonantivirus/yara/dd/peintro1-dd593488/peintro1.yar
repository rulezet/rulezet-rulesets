import "pe"
rule peintro1
{
	meta:
		author = "PEiD"
		description = "PE Intro 1.0 -> Predator NLS"
		group = "146"
		function = "0"
	strings:
		$a0 = { 8B 04 24 9C 60 E8 ?? ?? ?? ?? 5D 81 ED 0A 45 40 ?? 80 BD 67 44 40 ?? ?? 0F 85 48 }
	condition:
		$a0 at pe.entry_point
}