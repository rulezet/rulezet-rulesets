import "pe"
rule CDCopsII
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 53 60 BD [4] 8D 45 ?? 8D 5D ?? E8 [4] 8D }

condition:
		$a0 at pe.entry_point
}