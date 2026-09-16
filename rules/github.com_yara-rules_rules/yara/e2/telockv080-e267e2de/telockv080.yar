import "pe"
rule tElockv080
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 60 E8 F9 11 00 00 C3 83 }

condition:
		$a0 at pe.entry_point
}