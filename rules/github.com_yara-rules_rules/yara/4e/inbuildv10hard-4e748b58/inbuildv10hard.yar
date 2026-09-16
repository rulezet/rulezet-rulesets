import "pe"
rule Inbuildv10hard
{
      meta:
		author="malware-lu"
strings:
		$a0 = { B9 [2] BB [2] 2E [2] 2E [2] 43 E2 }

condition:
		$a0 at pe.entry_point
}