import "pe"
rule EXEStealthv272
{
      meta:
		author="malware-lu"
strings:
		$a0 = { EB 00 EB 2F 53 68 61 72 65 77 61 72 65 20 2D 20 }

condition:
		$a0 at pe.entry_point
}