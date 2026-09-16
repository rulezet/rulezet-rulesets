import "pe"
rule E2CbyDoP
{
      meta:
		author="malware-lu"
strings:
		$a0 = { BE [2] BF [2] B9 [2] FC 57 F3 A5 C3 }

condition:
		$a0 at pe.entry_point
}