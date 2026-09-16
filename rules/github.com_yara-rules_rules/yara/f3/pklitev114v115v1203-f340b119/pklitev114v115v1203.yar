import "pe"
rule PKLITEv114v115v1203
{
      meta:
		author="malware-lu"
strings:
		$a0 = { B8 [2] BA [2] 05 [2] 3B [3] 72 ?? B4 09 BA ?? 01 CD 21 CD 20 4E 6F }

condition:
		$a0 at pe.entry_point
}