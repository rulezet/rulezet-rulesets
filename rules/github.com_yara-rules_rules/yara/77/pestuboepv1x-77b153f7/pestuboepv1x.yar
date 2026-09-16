rule PEStubOEPv1x
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 40 48 BE 00 [2] 00 40 48 60 33 C0 B8 [3] 00 FF E0 C3 C3 }

condition:
		$a0
}