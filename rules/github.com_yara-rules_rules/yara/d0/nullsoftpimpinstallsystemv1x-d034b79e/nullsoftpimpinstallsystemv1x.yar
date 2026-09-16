import "pe"
rule NullsoftPIMPInstallSystemv1x
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 83 EC 5C 53 55 56 57 FF 15 [3] 00 }

condition:
		$a0 at pe.entry_point
}