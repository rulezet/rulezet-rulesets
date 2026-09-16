import "pe"
rule SimbiOZPoly21Extranger
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 55 50 8B C4 83 C0 04 C7 00 [4] 58 C3 90 }

condition:
		$a0 at pe.entry_point
}