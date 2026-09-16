import "pe"
rule PECryptv102
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E8 [4] 5B 83 EB 05 EB 04 52 4E 44 }

condition:
		$a0 at pe.entry_point
}