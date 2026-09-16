import "pe"
rule PELOCKnt204
{
      meta:
		author="malware-lu"
strings:
		$a0 = { EB 03 CD 20 C7 1E EB 03 CD 20 EA 9C EB 02 EB 01 EB 01 EB 60 }

condition:
		$a0 at pe.entry_point
}