import "pe"
rule HACKSTOPv118
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 52 BA [2] 5A EB ?? 9A [4] 30 CD 21 [3] FD 02 [2] CD 20 0E 1F 52 BA [2] 5A EB }

condition:
		$a0 at pe.entry_point
}