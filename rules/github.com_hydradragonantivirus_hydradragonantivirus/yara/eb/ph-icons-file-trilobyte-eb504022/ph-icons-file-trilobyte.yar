import "pe"
rule _PH_Icons_file_Trilobyte_
{
	meta:
		description = "PH Icons file (Trilobyte)"
	strings:
		$0 = {69 63 6F 6E 01 00 10 00 10}
	condition:
		$0 at pe.entry_point
}