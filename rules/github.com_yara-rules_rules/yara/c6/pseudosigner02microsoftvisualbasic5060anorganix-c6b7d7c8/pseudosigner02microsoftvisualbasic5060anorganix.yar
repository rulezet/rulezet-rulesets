import "pe"
rule PseudoSigner02MicrosoftVisualBasic5060Anorganix
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 68 [4] E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00 }

condition:
		$a0 at pe.entry_point
}