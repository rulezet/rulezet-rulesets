import "pe"
rule _ARJ_Archive_
{
	meta:
		description = "ARJ Archive"
	strings:
		$0 = {60 EA}
	condition:
		$0 at pe.entry_point
}