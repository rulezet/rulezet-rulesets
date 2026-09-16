import "pe"
rule VxKeypress1212
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E8 [2] E8 [2] E8 [2] E8 [4] E8 [4] E8 [4] EA [4] 1E 33 DB 8E DB BB }

condition:
		$a0 at pe.entry_point
}