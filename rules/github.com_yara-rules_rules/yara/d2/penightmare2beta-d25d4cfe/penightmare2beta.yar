import "pe"
rule PENightMare2Beta
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 60 E9 [4] EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A }

condition:
		$a0 at pe.entry_point
}