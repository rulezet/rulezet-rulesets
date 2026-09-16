import "pe"
rule _PE_Pack_v10_
{
	meta:
		description = "PE Pack v1.0"
	strings:
		$0 = {FC 8B 35 70 01 40 83 EE 40 6A 40 68 30}
	condition:
		$0 at pe.entry_point
}