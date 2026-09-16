import "pe"
rule KBySV022shoooo
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 68 [4] E8 01 00 00 00 C3 C3 11 55 07 8B EC B8 [4] E8 }

condition:
		$a0 at pe.entry_point
}