import "pe"
rule FSGv110EngbartxtWinRARSFX
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 80 E9 A1 C1 C1 13 68 E4 16 75 46 C1 C1 05 5E EB 01 9D 68 64 86 37 46 EB 02 8C E0 5F F7 D0 }
	$a1 = { EB 01 02 EB 02 CD 20 B8 80 ?? 42 00 EB 01 55 BE F4 00 00 00 13 DF 13 D8 0F B6 38 D1 F3 F7 }

condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}