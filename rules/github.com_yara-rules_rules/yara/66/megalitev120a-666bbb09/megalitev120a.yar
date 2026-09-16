import "pe"
rule MEGALITEv120a
{
      meta:
		author="malware-lu"
strings:
		$a0 = { B8 [2] BA [2] 05 [2] 3B 2D 73 ?? 72 ?? B4 09 BA [2] CD 21 CD 90 }

condition:
		$a0 at pe.entry_point
}