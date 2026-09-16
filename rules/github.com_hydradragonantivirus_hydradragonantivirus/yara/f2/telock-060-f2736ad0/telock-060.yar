import "pe"
rule telock_060
{
	meta:
		author = "PEiD"
		description = "tElock 0.60 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { E9 ?? ?? ?? ?? 60 E8 ?? ?? ?? ?? 58 83 C0 08 F3 EB FF E0 83 C0 28 50 E8 ?? ?? ?? ?? 5E B3 33 8D 46 0E 8D 76 31 28 18 F8 73 ?? C3 8B FE B9 BE 01 }
	condition:
		$a0 at pe.entry_point
}