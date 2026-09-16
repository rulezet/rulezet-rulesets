import "pe"
rule PackanoidArkanoid
{
      meta:
		author="malware-lu"
strings:
		$a0 = { BF 00 10 40 00 BE [3] 00 E8 9D 00 00 00 B8 }

condition:
		$a0 at pe.entry_point
}