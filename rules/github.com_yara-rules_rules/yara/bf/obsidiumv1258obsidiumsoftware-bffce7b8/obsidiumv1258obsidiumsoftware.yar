import "pe"
rule ObsidiumV1258ObsidiumSoftware
{
      meta:
		author="malware-lu"
strings:
		$a0 = { EB 01 ?? E8 ?? 00 00 00 }

condition:
		$a0 at pe.entry_point
}