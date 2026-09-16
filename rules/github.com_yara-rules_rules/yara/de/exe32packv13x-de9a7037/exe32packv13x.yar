import "pe"
rule EXE32Packv13x
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 3B ?? 74 02 81 83 55 3B ?? 74 02 81 ?? 53 3B ?? 74 01 [5] 02 81 [2] E8 [4] 3B 74 01 ?? 5D 8B D5 81 ED }

condition:
		$a0 at pe.entry_point
}