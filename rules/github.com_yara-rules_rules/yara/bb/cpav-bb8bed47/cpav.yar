import "pe"
rule CPAV: Packer PEiD
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E8 [2] 4D 5A B1 01 93 01 00 00 02 }

condition:
		$a0 at pe.entry_point
}