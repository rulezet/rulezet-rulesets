import "pe"
rule UnknownbySMT
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 60 BE [4] 8D BE [4] 83 [2] 57 EB }

condition:
		$a0 at pe.entry_point
}