import "pe"
rule pelocknt202c
{
	meta:
		author = "PEiD"
		description = "PE Lock NT 2.02c -> :MARQUiS:"
		group = "148"
		function = "0"
	strings:
		$a0 = { EB 02 C7 85 1E EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 02 CD }
	condition:
		$a0 at pe.entry_point
}