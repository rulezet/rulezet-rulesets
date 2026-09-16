rule VMProtect106107PolyTech
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 9C 60 68 00 00 00 00 8B 74 24 28 BF [4] FC 89 F3 03 34 24 AC 00 D8 }

condition:
		$a0
}