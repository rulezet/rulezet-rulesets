import "pe"
rule SimpleUPXCryptorV3042005MANtiCORE
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 60 B8 [4] B9 [8] E2 FA 61 68 [4] C3 }

condition:
		$a0 at pe.entry_point
}