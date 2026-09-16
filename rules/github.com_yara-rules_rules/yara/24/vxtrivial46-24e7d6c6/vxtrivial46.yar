import "pe"
rule VxTrivial46
{
      meta:
		author="malware-lu"
strings:
		$a0 = { B4 4E B1 20 BA [2] CD 21 BA [2] B8 ?? 3D CD 21 }

condition:
		$a0 at pe.entry_point
}