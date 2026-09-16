import "pe"
rule JDPack: Packer PEiD
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 60 E8 [4] 5D 8B D5 81 ED [4] 2B 95 [4] 81 EA 06 [3] 89 95 [4] 83 BD 45 }

condition:
		$a0 at pe.entry_point
}