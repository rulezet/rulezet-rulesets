import "pe"
rule PEDiminisherV01Teraphy
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 53 51 52 56 57 55 E8 00 00 00 00 }

condition:
		$a0 at pe.entry_point
}