import "pe"
rule SDProtectorV11xRandyLi
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 55 8B EC 6A FF 68 [4] 68 88 88 88 08 64 A1 }

condition:
		$a0 at pe.entry_point
}