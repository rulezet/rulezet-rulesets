import "pe"
rule GameGuardv20065xxdllsignbyhot_UNP
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 31 FF 74 06 61 E9 4A 4D 50 30 BA 4C 00 00 00 80 7C 24 08 01 0F 85 ?? 01 00 00 60 BE 00 }

condition:
		$a0 at pe.entry_point
}