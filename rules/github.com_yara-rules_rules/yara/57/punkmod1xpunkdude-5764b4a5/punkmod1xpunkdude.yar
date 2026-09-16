rule PuNkMoD1xPuNkDuDe
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 94 B9 [2] 00 00 BC [4] 80 34 0C }

condition:
		$a0
}