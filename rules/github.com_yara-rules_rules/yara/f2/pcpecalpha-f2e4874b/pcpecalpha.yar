import "pe"
rule PCPECalpha
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 53 51 52 56 57 55 E8 [4] 5D 8B CD 81 [4] ?? 2B [4] ?? 83 }

condition:
		$a0 at pe.entry_point
}