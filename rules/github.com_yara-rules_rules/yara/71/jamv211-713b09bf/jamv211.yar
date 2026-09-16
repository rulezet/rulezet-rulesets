import "pe"
rule JAMv211
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 50 06 16 07 BE [2] 8B FE B9 [2] FD FA F3 2E A5 FB 06 BD [2] 55 CB }

condition:
		$a0 at pe.entry_point
}