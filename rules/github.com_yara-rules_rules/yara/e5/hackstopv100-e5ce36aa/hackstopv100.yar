import "pe"
rule HACKSTOPv100
{
      meta:
		author="malware-lu"
strings:
		$a0 = { FA BD [2] FF E5 6A 49 48 0C ?? E4 ?? 3F 98 3F }

condition:
		$a0 at pe.entry_point
}