import "pe"
rule _tElock_v090_
{
	meta:
		description = "tElock v0.90"
	strings:
		$0 = {E9 7E E9 FF}
	condition:
		$0 at pe.entry_point
}