import "pe"
rule VxSK
{
      meta:
		author="malware-lu"
strings:
		$a0 = { CD 20 B8 03 00 CD 10 51 E8 00 00 5E 83 EE 09 }

condition:
		$a0 at pe.entry_point
}