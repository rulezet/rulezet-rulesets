import "pe"
rule PseudoSigner01YodasProtector102Anorganix
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E8 03 00 00 00 EB 01 90 90 E9 }

condition:
		$a0 at pe.entry_point
}