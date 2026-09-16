import "pe"
rule PELockNTv204
{
      meta:
		author="malware-lu"
strings:
		$a0 = { EB ?? CD [5] CD [5] EB ?? EB ?? EB ?? EB ?? CD [5] E8 [4] E9 [4] 50 C3 }

condition:
		$a0 at pe.entry_point
}