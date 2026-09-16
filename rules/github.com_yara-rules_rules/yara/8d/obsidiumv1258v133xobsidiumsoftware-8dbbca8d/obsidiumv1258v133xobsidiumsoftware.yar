import "pe"
rule ObsidiumV1258V133XObsidiumSoftware
{
      meta:
		author="malware-lu"
strings:
		$a0 = { EB 01 ?? E8 ?? 00 00 00 EB 02 [2] EB }

condition:
		$a0 at pe.entry_point
}