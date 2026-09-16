import "pe"
rule Upackv01xv02xDwing
{
      meta:
		author="malware-lu"
strings:
		$a0 = { BE 88 01 [2] AD 8B F8 95 }

condition:
		$a0 at pe.entry_point
}