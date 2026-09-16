import "pe"
rule _UPolyX_03_by_delikon_
{
	meta:
		description = "UPolyX 0.3 by delikon"
	strings:
		$0 = {8B ?? B9 ?? ?? ?? ?? 80}
	condition:
		$0 at pe.entry_point
}