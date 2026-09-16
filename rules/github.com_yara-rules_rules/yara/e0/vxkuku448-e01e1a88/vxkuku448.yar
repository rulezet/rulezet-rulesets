import "pe"
rule VxKuku448
{
      meta:
		author="malware-lu"
strings:
		$a0 = { AE 75 ED E2 F8 89 3E [2] BA [2] 0E 07 BF [2] EB }

condition:
		$a0 at pe.entry_point
}