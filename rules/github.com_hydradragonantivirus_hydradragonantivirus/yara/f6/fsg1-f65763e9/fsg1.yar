import "pe"
rule fsg1
{
	meta:
		author = "PEiD"
		description = "FSG 1.0 -> dulek/xt"
		group = "123"
		function = "0"
	strings:
		$a0 = { BB D0 01 40 ?? BF ?? 10 40 ?? BE ?? ?? ?? ?? 53 E8 0A ?? ?? ?? 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B }
	condition:
		$a0 at pe.entry_point
}