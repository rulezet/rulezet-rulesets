import "pe"
rule _UPX_050__070_
{
	meta:
		description = "UPX 0.50 - 0.70"
	strings:
		$0 = {60 E8 00 00 00 00 58 83 E8 3D}
	condition:
		$0 at pe.entry_point
}