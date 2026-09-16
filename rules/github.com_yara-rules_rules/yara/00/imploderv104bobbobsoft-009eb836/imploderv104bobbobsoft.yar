import "pe"
rule Imploderv104BoBBobSoft
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 60 E8 A0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 [3] 2E [3] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }

condition:
		$a0 at pe.entry_point
}