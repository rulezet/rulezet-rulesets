import "pe"
rule _PECompact_v20_
{
	meta:
		description = "PECompact v2.0"
	strings:
		$0 = {B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D}
		$1 = {B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}