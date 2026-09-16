import "pe"
rule nbuildv10soft
{
      meta:
		author="malware-lu"
strings:
		$a0 = { B9 [2] BB [2] C0 [2] 80 [2] 43 E2 }

condition:
		$a0 at pe.entry_point
}