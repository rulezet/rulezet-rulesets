import "pe"
rule VxVCLencrypted
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 01 B9 [2] 81 34 [2] 46 46 E2 F8 C3 }
	$a1 = { 01 B9 [2] 81 35 [2] 47 47 E2 F8 C3 }

condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}