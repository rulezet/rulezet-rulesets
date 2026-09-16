import "pe"
rule SoftProtectwwwsoftprotectbyru
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E8 [4] 8D [5] C7 00 00 00 00 00 E8 [4] E8 [4] 8D [5] 50 E8 [4] 83 [5] 01 }

condition:
		$a0 at pe.entry_point
}