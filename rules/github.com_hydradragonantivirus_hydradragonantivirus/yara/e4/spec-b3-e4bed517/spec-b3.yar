import "pe"
rule _SPEC_b3_
{
	meta:
		description = "SPEC b3"
	strings:
		$0 = {BA ?? FF E2 BA ?? B8 89 02 83 C2 03 B8 89 02 83 C2 FD FF}
	condition:
		$0 at pe.entry_point
}