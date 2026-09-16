import "pe"
rule VOBProtectCD
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 5F 81 EF [4] BE [2] 40 ?? 8B 87 [4] 03 C6 57 56 8C A7 [4] FF 10 89 87 [4] 5E 5F }

condition:
		$a0 at pe.entry_point
}