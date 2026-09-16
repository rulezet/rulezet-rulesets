import "pe"
rule PseudoSigner01WATCOMCCEXEAnorganix
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E9 00 00 00 00 90 90 90 90 57 41 E9 }

condition:
		$a0 at pe.entry_point
}