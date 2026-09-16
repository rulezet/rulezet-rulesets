import "pe"
rule PseudoSigner02MinGWGCC2xAnorganix
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45 }

condition:
		$a0 at pe.entry_point
}