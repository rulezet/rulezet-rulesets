import "pe"
rule ObsidiumV125ObsidiumSoftware
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 0D 33 C0 C3 }

condition:
		$a0 at pe.entry_point
}