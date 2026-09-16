import "pe"
rule EXEStealthv27
{
      meta:
		author="malware-lu"
strings:
		$a0 = { EB 00 60 EB 00 E8 00 00 00 00 5D 81 ED D3 26 40 }

condition:
		$a0 at pe.entry_point
}