import "pe"
rule _PseudoSigner_02_XCR_011__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [XCR 0.11] --> Anorganix"
	strings:
		$0 = {60 8B F0 33 DB 83 C3 01 83 C0 01}
	condition:
		$0 at pe.entry_point
}