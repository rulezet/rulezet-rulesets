import "pe"
rule _PKLITE_v100_v103_
{
	meta:
		description = "PKLITE v1.00, v1.03"
	strings:
		$0 = {B8 ?? ?? BA ?? ?? 8C DB 03 D8 3B}
	condition:
		$0 at pe.entry_point
}