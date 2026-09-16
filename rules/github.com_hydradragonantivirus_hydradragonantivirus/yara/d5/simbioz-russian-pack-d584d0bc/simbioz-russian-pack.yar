import "pe"
rule _SimbiOZ__Russian_PacK_
{
	meta:
		description = "SimbiOZ -> Russian PacK"
	strings:
		$0 = {50 60 E8 00 00 00 00 5D 81 ED 07 10 40 00 68 80 0B 00 00 8D 85 1F 10 40 00 50 E8 84 0B 00 00}
	condition:
		$0 at pe.entry_point
}