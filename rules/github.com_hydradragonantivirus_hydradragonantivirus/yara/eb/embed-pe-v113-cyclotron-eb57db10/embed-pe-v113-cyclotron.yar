import "pe"
rule _Embed_PE_v113__cyclotron_
{
	meta:
		description = "Embed PE v1.13 -> cyclotron"
	strings:
		$0 = {83 EC 50 60 68 5D B9 52 5A E8 2F 99 00 00 DC 99 F3 57 05 68}
	condition:
		$0 at pe.entry_point
}