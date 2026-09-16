import "pe"
rule Upackv031betaDwing
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E9 [4] 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 [20] 31 }

condition:
		$a0 at pe.entry_point
}