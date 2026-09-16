import "pe"
rule PseudoSigner01DEF10Anorganix
{
      meta:
		author="malware-lu"
strings:
		$a0 = { BE 00 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 83 C1 01 E9 }

condition:
		$a0 at pe.entry_point
}