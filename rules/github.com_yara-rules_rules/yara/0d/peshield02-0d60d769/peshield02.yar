import "pe"
rule PESHiELD02
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 60 E8 00 00 00 00 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04 }

condition:
		$a0 at pe.entry_point
}