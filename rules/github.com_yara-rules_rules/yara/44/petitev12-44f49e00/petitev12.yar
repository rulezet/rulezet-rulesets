import "pe"
rule PEtitev12
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 9C 60 E8 CA [3] 03 ?? 04 ?? 05 ?? 06 ?? 07 ?? 08 }

condition:
		$a0 at pe.entry_point
}