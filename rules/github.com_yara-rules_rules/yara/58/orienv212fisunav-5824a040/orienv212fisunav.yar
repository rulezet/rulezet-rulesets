import "pe"
rule ORiENV212FisunAV
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E9 5D 01 00 00 CE D1 CE CD 0D }

condition:
		$a0 at pe.entry_point
}