import "pe"
rule _JRC_Archive_
{
	meta:
		description = "JRC Archive"
	strings:
		$0 = {4A 52 63 68 69 76 65}
	condition:
		$0 at pe.entry_point
}