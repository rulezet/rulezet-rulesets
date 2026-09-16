import "pe"
rule _SLR_OPTLINK_1_
{
	meta:
		description = "SLR (OPTLINK) (1)"
	strings:
		$0 = {87 C0 EB ?? 71 ?? 02 D8}
	condition:
		$0 at pe.entry_point
}