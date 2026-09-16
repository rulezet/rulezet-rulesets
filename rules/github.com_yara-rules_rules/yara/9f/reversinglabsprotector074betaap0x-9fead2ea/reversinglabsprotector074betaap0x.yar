import "pe"
rule ReversingLabsProtector074betaAp0x
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 68 00 00 41 00 E8 01 00 00 00 C3 C3 }

condition:
		$a0 at pe.entry_point
}