import "pe"
rule Upackv033v034BetaDwing
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 59 F3 A5 83 C8 FF 8B DF AB 40 AB 40 }

condition:
		$a0 at pe.entry_point
}