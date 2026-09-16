import "pe"
rule MicrosoftVisualCV80
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 6A 14 68 [4] E8 [4] BB 94 00 00 00 53 6A 00 8B [5] FF D7 50 FF [5] 8B F0 85 F6 75 0A 6A 12 E8 [4] 59 EB 18 89 1E 56 FF [5] 56 85 C0 75 14 50 FF D7 50 FF [5] B8 }

condition:
		$a0 at pe.entry_point
}