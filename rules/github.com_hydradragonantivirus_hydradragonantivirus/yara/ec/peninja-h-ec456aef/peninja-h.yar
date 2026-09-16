import "pe"
rule peninja_h
{
	meta:
		author = "PEiD"
		description = "PENinja modified -> +DZA"
		group = "152"
		function = "0"
	strings:
		$a0 = { 5D 8B C5 81 ED B2 2C 40 ?? 2B 85 94 3E 40 ?? 2D 71 02 ?? ?? 89 85 98 3E 40 ?? 0F B6 B5 9C 3E 40 ?? 8B FD }
	condition:
		$a0 at pe.entry_point
}