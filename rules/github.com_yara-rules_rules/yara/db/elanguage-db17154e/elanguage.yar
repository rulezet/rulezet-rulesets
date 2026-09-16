import "pe"
rule Elanguage
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E8 06 00 00 00 50 E8 ?? 01 00 00 55 8B EC 81 C4 F0 FE FF FF }

condition:
		$a0 at pe.entry_point
}