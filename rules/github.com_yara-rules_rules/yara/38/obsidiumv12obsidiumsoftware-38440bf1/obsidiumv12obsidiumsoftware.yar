import "pe"
rule ObsidiumV12ObsidiumSoftware
{
      meta:
		author="malware-lu"
strings:
		$a0 = { EB 02 [2] E8 77 1E 00 00 }

condition:
		$a0 at pe.entry_point
}