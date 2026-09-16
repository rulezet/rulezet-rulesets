import "pe"
rule CrinklerV03V04RuneLHStubbeandAskeSimonChristensen
{
      meta:
		author="malware-lu"
strings:
		$a0 = { B8 00 00 42 00 31 DB 43 EB 58 }

condition:
		$a0 at pe.entry_point
}