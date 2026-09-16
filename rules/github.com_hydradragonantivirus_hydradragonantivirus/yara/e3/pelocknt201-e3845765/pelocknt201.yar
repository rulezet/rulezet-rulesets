import "pe"
rule pelocknt201
{
	meta:
		author = "PEiD"
		description = "PE Lock NT 2.01 -> :MARQUiS:"
		group = "148"
		function = "0"
	strings:
		$a0 = { EB 03 CD 20 EB EB 01 EB 1E EB 01 EB EB 02 CD 20 9C EB 03 CD }
	condition:
		$a0 at pe.entry_point
}