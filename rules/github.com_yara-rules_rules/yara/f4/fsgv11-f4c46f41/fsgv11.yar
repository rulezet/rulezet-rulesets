import "pe"
rule FSGv11
{
      meta:
		author="malware-lu"
strings:
		$a0 = { BB D0 01 40 ?? BF ?? 10 40 ?? BE [4] FC B2 80 8A 06 46 88 07 47 02 D2 75 05 8A 16 }

condition:
		$a0 at pe.entry_point
}