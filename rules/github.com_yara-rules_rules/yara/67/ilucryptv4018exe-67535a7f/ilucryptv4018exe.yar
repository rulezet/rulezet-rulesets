import "pe"
rule iLUCRYPTv4018exe
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 8B EC FA C7 [4] 4C 4C C3 FB BF [2] B8 [2] 2E [2] D1 C8 4F 81 }

condition:
		$a0 at pe.entry_point
}