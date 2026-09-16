import "pe"
rule _PseudoSigner_01_VBOX_43_MTE_
{
	meta:
		description = "PseudoSigner 0.1 [VBOX 4.3 MTE"
	strings:
		$0 = {0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 E9}
		$1 = {0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 E9}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}