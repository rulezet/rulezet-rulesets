import "pe"
rule WWPack32v100v111v112v120
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 53 55 8B E8 33 DB EB 60 0D 0A 0D 0A 57 57 50 61 63 6B 33 32 }

condition:
		$a0 at pe.entry_point
}