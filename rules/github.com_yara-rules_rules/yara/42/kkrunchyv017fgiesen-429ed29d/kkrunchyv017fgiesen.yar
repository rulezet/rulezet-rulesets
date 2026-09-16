rule kkrunchyv017FGiesen
{
      meta:
		author="malware-lu"
strings:
		$a0 = { FC FF 4D 08 31 D2 8D 7D 30 BE }

condition:
		$a0
}