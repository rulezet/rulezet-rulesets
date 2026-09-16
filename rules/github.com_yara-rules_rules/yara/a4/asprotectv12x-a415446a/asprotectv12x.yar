import "pe"
rule ASProtectv12x
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 00 00 68 01 [3] C3 AA }

condition:
		$a0 at pe.entry_point
}