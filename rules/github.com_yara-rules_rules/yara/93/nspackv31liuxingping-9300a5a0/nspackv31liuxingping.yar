import "pe"
rule NsPacKV31LiuXingPing
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D [4] 8A 03 3C 00 74 }

condition:
		$a0 at pe.entry_point
}