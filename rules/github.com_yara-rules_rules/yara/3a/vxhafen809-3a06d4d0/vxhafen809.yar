import "pe"
rule VxHafen809
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E8 [2] 1C ?? 81 EE [2] 50 1E 06 8C C8 8E D8 06 33 C0 8E C0 26 [3] 07 3D }

condition:
		$a0 at pe.entry_point
}