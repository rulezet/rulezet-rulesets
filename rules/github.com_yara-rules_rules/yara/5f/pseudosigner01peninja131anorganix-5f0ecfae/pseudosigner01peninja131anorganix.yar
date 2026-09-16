import "pe"
rule PseudoSigner01PENinja131Anorganix
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 E9 }

condition:
		$a0 at pe.entry_point
}