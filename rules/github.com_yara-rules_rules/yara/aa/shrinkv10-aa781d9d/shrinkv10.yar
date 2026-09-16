import "pe"
rule Shrinkv10
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 50 9C FC BE [2] BF [2] 57 B9 [2] F3 A4 8B [3] BE [2] BF [2] F3 A4 C3 }

condition:
		$a0 at pe.entry_point
}