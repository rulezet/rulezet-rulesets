import "pe"
rule _DWC_Archive_
{
	meta:
		description = "DWC Archive"
	strings:
		$0 = {44 57 43}
	condition:
		$0 at pe.entry_point
}