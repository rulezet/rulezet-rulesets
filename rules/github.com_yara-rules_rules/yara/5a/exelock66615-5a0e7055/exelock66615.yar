import "pe"
rule EXELOCK66615
{
      meta:
		author="malware-lu"
strings:
		$a0 = { BA [2] BF [2] EB ?? EA [4] 79 ?? 7F ?? 7E ?? 1C ?? 48 78 ?? E3 ?? 45 14 ?? 5A E9 }

condition:
		$a0 at pe.entry_point
}