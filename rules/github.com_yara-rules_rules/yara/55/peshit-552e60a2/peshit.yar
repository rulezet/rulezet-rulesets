import "pe"
rule PEShit: Packer PEiD
{
      meta:
		author="malware-lu"
strings:
		$a0 = { B8 [4] B9 [4] 83 F9 00 7E 06 80 30 ?? 40 E2 F5 E9 [3] FF }

condition:
		$a0 at pe.entry_point
}