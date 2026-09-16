import "pe"
rule _XCR_v011_
{
	meta:
		description = "XCR v0.11"
	strings:
		$0 = {60 9C E8 8B DD 5D 81 ED 89}
	condition:
		$0 at pe.entry_point
}