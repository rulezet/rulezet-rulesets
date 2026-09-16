import "pe"
rule _Interchange_Format_File_IFF_type_WVQA_
{
	meta:
		description = "Interchange Format File (IFF), type WVQA"
	strings:
		$0 = {46 4F 52 4D ?? ?? ?? ?? 57 56 51 41 56 51 48 44}
	condition:
		$0 at pe.entry_point
}