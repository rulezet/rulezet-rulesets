import "pe"
rule eXpressorv145CGSoftLabs
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C }

condition:
		$a0 at pe.entry_point
}