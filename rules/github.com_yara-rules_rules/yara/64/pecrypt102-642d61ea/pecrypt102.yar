import "pe"
rule PECrypt102
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 85 C0 73 02 F7 }

condition:
		$a0 at pe.entry_point
}