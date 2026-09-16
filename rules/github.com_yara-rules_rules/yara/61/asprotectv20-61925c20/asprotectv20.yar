rule ASProtectv20
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 68 01 ?? 40 00 E8 01 00 00 00 C3 C3 }

condition:
		$a0
}