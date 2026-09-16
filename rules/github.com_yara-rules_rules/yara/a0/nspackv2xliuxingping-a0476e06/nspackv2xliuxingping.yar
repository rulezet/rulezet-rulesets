rule nSpackV2xLiuXingPing
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 }

condition:
		$a0
}