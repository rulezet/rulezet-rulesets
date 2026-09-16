rule codeCrypter031
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 50 58 53 5B 90 BB [2] 40 00 FF E3 90 CC CC CC 55 8B EC 5D C3 CC CC CC CC CC CC CC CC CC CC CC }

condition:
		$a0
}