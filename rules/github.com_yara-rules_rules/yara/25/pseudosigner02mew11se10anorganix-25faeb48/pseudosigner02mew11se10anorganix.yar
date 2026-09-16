import "pe"
rule PseudoSigner02MEW11SE10Anorganix
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E9 09 00 00 00 00 00 00 02 00 00 00 0C 90 }

condition:
		$a0 at pe.entry_point
}