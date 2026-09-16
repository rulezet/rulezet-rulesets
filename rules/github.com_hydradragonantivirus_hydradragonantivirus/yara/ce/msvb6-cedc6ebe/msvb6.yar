import "pe"
rule MSVB6
{
	meta:
		author="_pusher_"
		date = "2016-08"
		linker = "6.00"
	condition:
		pe.rich_signature.version(8041) and pe.rich_signature.version(8169) and pe.rich_signature.toolid(9) or
		pe.rich_signature.version(8169) and pe.rich_signature.toolid(13)
}