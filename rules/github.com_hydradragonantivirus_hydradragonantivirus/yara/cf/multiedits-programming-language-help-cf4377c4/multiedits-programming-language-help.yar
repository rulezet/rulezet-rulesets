import "pe"
rule _MultiEdits_Programming_Language_help_
{
	meta:
		description = "MultiEdit`s Programming Language help"
	strings:
		$0 = {0C 2A 20}
	condition:
		$0 at pe.entry_point
}