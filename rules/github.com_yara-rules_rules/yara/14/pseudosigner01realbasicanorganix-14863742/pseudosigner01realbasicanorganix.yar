import "pe"
rule PseudoSigner01REALBasicAnorganix
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01 E9 }

condition:
		$a0 at pe.entry_point
}