rule Safe20
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 83 EC 10 53 56 57 E8 C4 01 00 }

condition:
		$a0
}