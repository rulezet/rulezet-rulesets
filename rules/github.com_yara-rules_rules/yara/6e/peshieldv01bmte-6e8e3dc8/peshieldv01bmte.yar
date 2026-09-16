import "pe"
rule PESHiELDv01bMTE
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E8 [26] B9 1B 01 [2] D1 }

condition:
		$a0 at pe.entry_point
}