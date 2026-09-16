import "pe"
rule WIBUKeyV410Ahttpwibucomus
{
      meta:
		author="malware-lu"
strings:
		$a0 = { F7 05 [4] FF 00 00 00 75 12 }

condition:
		$a0 at pe.entry_point
}