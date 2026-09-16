import "pe"
rule PEPACKv10byANAKiN1998
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 74 ?? E9 [4] 00 00 00 00 }

condition:
		$a0 at pe.entry_point
}