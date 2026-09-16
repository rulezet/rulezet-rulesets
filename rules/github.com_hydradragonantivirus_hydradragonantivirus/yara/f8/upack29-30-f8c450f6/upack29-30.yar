import "pe"
rule upack29_30
{
	meta:
		author = "PEiD"
		description = "Upack 0.29 / 0.30 beta -> Dwing"
		group = "444"
		function = "0"
	strings:
		$a0 = { BE ?? ?? ?? ?? AD 8B F8 95 AD 91 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 57 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 }
	condition:
		$a0 at pe.entry_point
}