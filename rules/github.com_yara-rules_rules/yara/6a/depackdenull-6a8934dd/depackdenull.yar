import "pe"
rule dePACKdeNULL
{
      meta:
		author="malware-lu"
strings:
		$a0 = { EB 01 DD 60 68 00 [3] 68 [2] 00 00 E8 ?? 00 00 00 }
	$a1 = { EB 01 DD 60 68 00 [3] 68 [3] 00 E8 ?? 00 00 00 [128] D2 }

condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}