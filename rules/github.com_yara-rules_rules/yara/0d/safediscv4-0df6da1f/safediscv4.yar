rule SafeDiscv4
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 42 6F 47 5F }

condition:
		$a0
}