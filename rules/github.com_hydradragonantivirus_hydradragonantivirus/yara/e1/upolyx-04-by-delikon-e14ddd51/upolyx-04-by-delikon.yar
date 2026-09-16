import "pe"
rule _UPolyx_04_by_delikon_
{
	meta:
		description = "UPolyx 0.4 by delikon"
	strings:
		$0 = {C3 ?? ?? ?? ?? ?? 83 EC 04 89}
	condition:
		$0 at pe.entry_point
}