import "pe"
rule _FreeHand_Graphics_format_
{
	meta:
		description = "FreeHand Graphics format"
	strings:
		$0 = {41 47 44 32}
	condition:
		$0 at pe.entry_point
}