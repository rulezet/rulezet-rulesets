rule Upackv037v038BetaStripbaserelocationtableOptionDwing
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 33 }

condition:
		$a0
}