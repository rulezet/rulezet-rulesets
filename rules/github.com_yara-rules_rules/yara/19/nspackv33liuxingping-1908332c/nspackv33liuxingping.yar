import "pe"
rule NsPacKV33LiuXingPing
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 [4] 80 38 00 74 }

condition:
		$a0 at pe.entry_point
}