import "pe"
rule ASProtectvxx
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 60 [5] 90 5D [11] 03 DD }

condition:
		$a0 at pe.entry_point
}