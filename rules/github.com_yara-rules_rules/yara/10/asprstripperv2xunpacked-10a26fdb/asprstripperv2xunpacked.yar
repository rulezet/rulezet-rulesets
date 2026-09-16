import "pe"
rule ASPRStripperv2xunpacked
{
      meta:
		author="malware-lu"
strings:
		$a0 = { BB [4] E9 [4] 60 9C FC BF [4] B9 [4] F3 AA 9D 61 C3 55 8B EC }

condition:
		$a0 at pe.entry_point
}