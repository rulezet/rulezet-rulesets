import "pe"
rule ObsidiumV1300ObsidiumSoftware
{
      meta:
		author="malware-lu"
strings:
		$a0 = { EB 04 [4] E8 29 00 00 00 }
	$a1 = { EB 04 [4] E8 ?? 00 00 00 }

condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}