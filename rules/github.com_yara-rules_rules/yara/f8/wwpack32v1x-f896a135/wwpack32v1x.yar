import "pe"
rule WWPack32v1x
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 53 55 8B E8 33 DB EB 60 }

condition:
		$a0 at pe.entry_point
}