import "pe"
rule GamehouseMediaProtectorVersionUnknown
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 68 [4] 6A 00 FF 15 [4] 50 FF 15 [3] 00 00 00 00 00 00 00 00 }

condition:
		$a0 at pe.entry_point
}