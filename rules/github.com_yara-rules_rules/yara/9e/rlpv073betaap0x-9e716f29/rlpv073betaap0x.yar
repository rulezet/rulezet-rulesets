rule RLPV073betaap0x
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 2E 72 6C 70 00 00 00 00 00 50 00 00 [12] 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 E0 }

condition:
		$a0
}