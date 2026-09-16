import "pe"
rule ASProtectv11
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 60 E9 ?? 04 [2] E9 [7] EE }

condition:
		$a0 at pe.entry_point
}