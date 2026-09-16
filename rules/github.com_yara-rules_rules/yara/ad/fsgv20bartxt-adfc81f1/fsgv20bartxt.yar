import "pe"
rule FSGv20bartxt
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 87 25 [3] 00 61 94 55 A4 B6 80 FF 13 }

condition:
		$a0 at pe.entry_point
}