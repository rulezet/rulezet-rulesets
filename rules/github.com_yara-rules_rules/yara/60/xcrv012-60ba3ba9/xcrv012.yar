import "pe"
rule XCRv012
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 60 9C E8 [4] 8B DD 5D 81 ED [4] 89 9D }

condition:
		$a0 at pe.entry_point
}