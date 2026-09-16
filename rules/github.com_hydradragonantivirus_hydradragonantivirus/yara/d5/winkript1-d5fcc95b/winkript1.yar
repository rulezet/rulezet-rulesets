import "pe"
rule winkript1
{
	meta:
		author = "PEiD"
		description = "Winkript 1.0 -> Mr. Crimson/WKT"
		group = "189"
		function = "0"
	strings:
		$a0 = { 33 C0 8B B8 ?? ?? ?? ?? 8B 90 04 ?? ?? ?? 85 FF 74 1B 33 C9 50 EB 0C 8A 04 39 C0 C8 04 34 1B 88 04 39 41 3B CA 72 F0 58 }
	condition:
		$a0 at pe.entry_point
}