import "pe"
rule ARCSFXArchive
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 8C C8 8C DB 8E D8 8E C0 89 [3] 2B C3 A3 [2] 89 [3] BE [2] B9 [2] BF [2] BA [2] FC AC 32 C2 8A D8 }

condition:
		$a0 at pe.entry_point
}