import "pe"
rule PECompactv20betaJeremyCollake
{
      meta:
		author="malware-lu"
strings:
		$a0 = { B8 [4] 05 [4] 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 }

condition:
		$a0 at pe.entry_point
}