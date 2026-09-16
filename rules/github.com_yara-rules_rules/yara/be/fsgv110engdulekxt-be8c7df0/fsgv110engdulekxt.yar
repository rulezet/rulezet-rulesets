import "pe"
rule FSGv110Engdulekxt
{
      meta:
		author="malware-lu"
strings:
		$a0 = { BB D0 01 40 ?? BF ?? 10 40 ?? BE }
	$a1 = { E8 01 00 00 00 [2] E8 ?? 00 00 00 }
	$a2 = { EB 01 ?? EB 02 [3] 80 [2] 00 }

condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point
}