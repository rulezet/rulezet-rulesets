import "pe"
rule _UPXHiT_001__djsiba_
{
	meta:
		description = "UPX$HiT 0.0.1 -> dj-siba"
	strings:
		$0 = {94 BC ?? ?? 43 00 B9 ?? 00 00 00 80 34 0C ?? E2 FA 94 FF E0 61 00 00 00 00 00 00}
	condition:
		$0 at pe.entry_point
}