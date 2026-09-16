import "pe"
rule PKLITEv112v115v1202
{
      meta:
		author="malware-lu"
strings:
		$a0 = { B8 [2] BA [2] 3B C4 73 }

condition:
		$a0 at pe.entry_point
}