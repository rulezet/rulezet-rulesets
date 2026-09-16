import "pe"
rule _CrunchPE_v50_
{
	meta:
		description = "Crunch/PE v5.0"
	strings:
		$0 = {EB 15 03 ?? ?? ?? 06}
	condition:
		$0 at pe.entry_point
}