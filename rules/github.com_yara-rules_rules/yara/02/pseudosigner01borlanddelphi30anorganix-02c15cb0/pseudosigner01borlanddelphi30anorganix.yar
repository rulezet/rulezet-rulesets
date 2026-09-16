import "pe"
rule PseudoSigner01BorlandDelphi30Anorganix
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 55 8B EC 83 C4 90 90 90 90 68 [4] 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

condition:
		$a0 at pe.entry_point
}