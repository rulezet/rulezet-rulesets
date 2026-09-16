import "pe"
rule ACProtectV20risco
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 68 [4] 68 [4] C3 C3 }

condition:
		$a0 at pe.entry_point
}