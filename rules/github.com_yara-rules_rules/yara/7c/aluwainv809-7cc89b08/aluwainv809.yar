import "pe"
rule Aluwainv809
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 8B EC 1E E8 [2] 9D 5E }

condition:
		$a0 at pe.entry_point
}