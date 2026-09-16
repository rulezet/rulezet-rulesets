import "pe"
rule VxXPEH4768
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E8 [2] 5B 81 [3] 50 56 57 2E [5] 2E [6] B8 01 00 50 B8 [2] 50 E8 }

condition:
		$a0 at pe.entry_point
}