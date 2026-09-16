rule PESpinv04x
{
      meta:
		author="malware-lu"
strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B }

condition:
		$a0
}