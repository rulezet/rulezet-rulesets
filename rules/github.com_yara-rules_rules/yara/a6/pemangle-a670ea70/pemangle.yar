import "pe"
rule PEMangle
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 60 9C BE [4] 8B FE B9 [4] BB 44 52 4F 4C AD 33 C3 }

condition:
		$a0 at pe.entry_point
}