import "pe"
rule PKLITEv100c2
{
      meta:
		author="malware-lu"
strings:
		$a0 = { BA [2] A1 [2] 2D [2] 8C CB 81 C3 [2] 3B C3 77 ?? 05 [2] 3B C3 77 ?? B4 09 BA [2] CD 21 CD 20 90 }

condition:
		$a0 at pe.entry_point
}