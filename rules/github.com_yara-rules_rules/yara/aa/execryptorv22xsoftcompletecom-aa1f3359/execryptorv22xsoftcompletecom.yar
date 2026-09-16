rule EXECryptorV22Xsoftcompletecom
{
      meta:
		author="malware-lu"
strings:
		$a0 = { FF E0 E8 04 00 00 00 FF FF FF FF 5E C3 00 }

condition:
		$a0
}