import "pe"
rule nullsoft_h
{
	meta:
		author = "PEiD"
		description = "Nullsoft PiMP stub 1.x"
		group = "24"
		function = "0"
	strings:
		$a0 = { C3 83 EC ?? 53 56 57 FF 15 }
	condition:
		$a0 at pe.entry_point
}