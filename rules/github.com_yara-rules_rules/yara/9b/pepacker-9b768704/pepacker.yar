import "pe"
rule PEPacker
{
      meta:
		author="malware-lu"
strings:
		$a0 = { FC 8B 35 70 01 40 ?? 83 EE 40 6A 40 68 ?? 30 10 }

condition:
		$a0 at pe.entry_point
}