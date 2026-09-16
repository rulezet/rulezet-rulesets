import "pe"
rule _ASPack_108_
{
	meta:
		description = "ASPack 1.08"
	strings:
		$0 = {90 90 90 75 01 90 E9}
	condition:
		$0 at pe.entry_point
}