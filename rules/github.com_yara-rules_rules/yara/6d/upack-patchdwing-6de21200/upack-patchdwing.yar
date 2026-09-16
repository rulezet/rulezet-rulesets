import "pe"
rule Upack_PatchDwing
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 81 3A 00 00 00 02 00 00 00 00 }

condition:
		$a0 at pe.entry_point
}