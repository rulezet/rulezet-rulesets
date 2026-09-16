import "pe"
rule _Crypta_II_30_
{
	meta:
		description = "Crypta II 3.0"
	strings:
		$0 = {26 83 36 53 A3 00 3B C4 5B 53 52 BA EB 04 5A EB FB 79 B9 37 00 81 F1 C1 11 51 B9 EB 04 59 EB FB 09 81 F1 C1 11 2E 80 37 80 43 E2 F9 3A D5 1E F7 C1 6A 4A F9 72 01 09 8E D9 90 53 BB EB 04 5B EB FB 09 F7 16 07 00 F7 C1 13 FE 52 BA EB 05 5A EB}
	condition:
		$0 at pe.entry_point
}