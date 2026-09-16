import "pe"
rule _PECompact_v184_
{
	meta:
		description = "PECompact v1.84"
	strings:
		$0 = {B8 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89}
	condition:
		$0 at pe.entry_point
}