import "pe"
rule ObsidiumV1304ObsidiumSoftware
{
      meta:
		author="malware-lu"
strings:
		$a0 = { EB 02 [2] E8 ?? 00 00 00 }

condition:
		$a0 at pe.entry_point
}