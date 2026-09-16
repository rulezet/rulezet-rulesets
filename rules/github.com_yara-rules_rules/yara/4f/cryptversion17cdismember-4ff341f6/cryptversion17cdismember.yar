import "pe"
rule CRYPTVersion17cDismember
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 0E 17 9C 58 F6 [2] 74 ?? E9 }

condition:
		$a0 at pe.entry_point
}