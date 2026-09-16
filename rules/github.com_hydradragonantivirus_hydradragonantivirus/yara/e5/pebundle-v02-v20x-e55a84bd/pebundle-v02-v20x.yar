import "pe"
rule _PEBundle_v02__v20x_
{
	meta:
		description = "PEBundle v0.2 - v2.0x"
	strings:
		$0 = {9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 40 87 DD 01 AD 01}
	condition:
		$0 at pe.entry_point
}