import "pe"
rule PseudoSigner01Gleam100Anorganix
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 0C 53 56 57 E8 24 02 00 FF E9 }

condition:
		$a0 at pe.entry_point
}