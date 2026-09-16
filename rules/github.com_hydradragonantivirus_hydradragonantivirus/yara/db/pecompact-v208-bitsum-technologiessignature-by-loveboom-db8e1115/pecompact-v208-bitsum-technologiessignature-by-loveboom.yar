import "pe"
rule _PeCompact_v208__Bitsum_Technologiessignature_by_loveboom_
{
	meta:
		description = "PeCompact v2.08 -> Bitsum Technologies(signature by loveboom)"
	strings:
		$0 = {B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D}
	condition:
		$0 at pe.entry_point
}