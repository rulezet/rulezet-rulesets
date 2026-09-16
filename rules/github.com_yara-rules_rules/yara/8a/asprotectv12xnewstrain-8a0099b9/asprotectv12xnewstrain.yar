import "pe"
rule ASProtectv12xNewStrain
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 68 01 [3] E8 01 [3] C3 C3 }

condition:
		$a0 at pe.entry_point
}