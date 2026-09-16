import "pe"
rule Obsidiumv1111
{
      meta:
		author="malware-lu"
strings:
		$a0 = { EB 02 [2] E8 E7 1C 00 00 }

condition:
		$a0 at pe.entry_point
}