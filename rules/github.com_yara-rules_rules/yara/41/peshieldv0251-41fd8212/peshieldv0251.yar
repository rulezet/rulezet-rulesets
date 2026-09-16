import "pe"
rule PESHiELDv0251
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 5D 83 ED 06 EB 02 EA 04 8D }

condition:
		$a0 at pe.entry_point
}