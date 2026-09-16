import "pe"
rule ASProtectv11MTE
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 60 E9 [4] 91 78 79 79 79 E9 }

condition:
		$a0 at pe.entry_point
}