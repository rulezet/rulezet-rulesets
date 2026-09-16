import "pe"
rule VxSonikYouth
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 8A 16 02 00 8A 07 32 C2 88 07 43 FE C2 81 FB }

condition:
		$a0 at pe.entry_point
}