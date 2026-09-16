import "pe"
rule VxSpanz
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E8 00 00 5E 81 EE [2] 8D 94 [2] B4 1A CD 21 C7 84 }

condition:
		$a0 at pe.entry_point
}