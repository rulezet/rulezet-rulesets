import "pe"
rule FSG131dulekxt
{
      meta:
		author="malware-lu"
strings:
		$a0 = { BE [3] 00 BF [3] 00 BB [3] 00 53 BB [3] 00 B2 80 }

condition:
		$a0 at pe.entry_point
}