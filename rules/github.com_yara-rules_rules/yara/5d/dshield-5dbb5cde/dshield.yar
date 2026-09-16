import "pe"
rule DSHIELD: Packer PEiD
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 06 E8 [2] 5E 83 EE ?? 16 17 9C 58 B9 [2] 25 [2] 2E }

condition:
		$a0 at pe.entry_point
}