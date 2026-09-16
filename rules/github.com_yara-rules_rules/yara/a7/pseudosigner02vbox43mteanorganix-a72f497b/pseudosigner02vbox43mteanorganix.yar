import "pe"
rule PseudoSigner02VBOX43MTEAnorganix
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 }

condition:
		$a0 at pe.entry_point
}