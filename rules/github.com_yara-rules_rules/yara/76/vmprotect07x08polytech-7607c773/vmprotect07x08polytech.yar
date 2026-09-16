rule VMProtect07x08PolyTech
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 5B 20 56 4D 50 72 6F 74 65 63 74 20 76 20 30 2E 38 20 28 43 29 20 50 6F 6C 79 54 65 63 68 20 5D }

condition:
		$a0
}