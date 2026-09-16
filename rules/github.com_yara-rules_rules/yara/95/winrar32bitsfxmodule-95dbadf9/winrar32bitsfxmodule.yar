import "pe"
rule WinRAR32bitSFXModule
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E9 [2] 00 00 00 00 00 00 90 90 90 [6] 00 ?? 00 [5] FF }

condition:
		$a0 at pe.entry_point
}