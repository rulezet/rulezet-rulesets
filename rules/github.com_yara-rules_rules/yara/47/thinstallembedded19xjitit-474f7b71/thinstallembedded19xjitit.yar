import "pe"
rule ThinstallEmbedded19XJitit
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 55 8B EC 51 53 56 57 6A 00 6A 00 FF 15 [4] 50 E8 87 FC FF FF 59 59 A1 [4] 8B 40 10 03 05 [4] 89 45 FC 8B 45 FC FF E0 5F 5E 5B C9 C3 00 00 00 }

condition:
		$a0 at pe.entry_point
}