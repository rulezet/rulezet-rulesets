import "pe"
rule PseudoSigner02ASProtectAnorganix
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD }

condition:
		$a0 at pe.entry_point
}