import "pe"
rule SimpleUPXCryptorv3042005OnelayerencryptionMANtiCORE
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 60 B8 [3] 00 B9 ?? 01 00 00 80 34 08 ?? E2 FA 61 68 [3] 00 C3 }

condition:
		$a0 at pe.entry_point
}