import "pe"
rule tElockv070mal
{
	meta:
		author="malware-lu"
strings:
		$a0 = { 60 E8 BD 10 00 00 C3 83 E2 00 F9 75 FA 70 }

condition:
		$a0 at pe.entry_point
}