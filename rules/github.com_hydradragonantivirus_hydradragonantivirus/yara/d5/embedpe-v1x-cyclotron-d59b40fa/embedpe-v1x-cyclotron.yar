import "pe"
rule _EmbedPE_V1X__cyclotron_
{
	meta:
		description = "EmbedPE V1.X -> cyclotron"
	strings:
		$0 = {83 EC 50 60 68 ?? ?? ?? ?? E8 ?? ?? 00 00}
	condition:
		$0 at pe.entry_point
}