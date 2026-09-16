import "pe"
rule tElockv071
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 60 E8 ED 10 00 00 C3 83 }

condition:
		$a0 at pe.entry_point
}