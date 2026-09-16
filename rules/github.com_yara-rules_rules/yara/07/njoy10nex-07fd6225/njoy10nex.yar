import "pe"
rule NJoy10NEX
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 9C 3B 40 00 E8 8C FC FF FF 6A 00 68 E4 39 40 00 6A 0A 6A 00 E8 40 FD FF FF E8 EF F5 FF FF 8D 40 00 }

condition:
		$a0 at pe.entry_point
}