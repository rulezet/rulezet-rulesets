import "pe"
rule _ASPack_v107b_DLL_
{
	meta:
		description = "ASPack v1.07b (DLL)"
	strings:
		$0 = {90 90 90 75}
	condition:
		$0 at pe.entry_point
}