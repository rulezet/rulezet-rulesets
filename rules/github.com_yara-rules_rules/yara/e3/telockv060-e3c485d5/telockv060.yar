import "pe"
rule tElockv060
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E9 00 00 00 00 60 E8 00 00 00 00 58 83 C0 08 }

condition:
		$a0 at pe.entry_point
}