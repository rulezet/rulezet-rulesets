import "pe"
rule _PEtite_v14_
{
	meta:
		description = "PEtite v1.4"
	strings:
		$0 = {66 9C 60 50 8B D8 03 68 54 BC 6A FF 50 14 8B}
		$1 = {B8 66 9C 60 50 8B D8 03 68 54 BC 6A FF 50 18 8B CC 8D A0 54 BC 8B C3 8D 90 E0 15}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}