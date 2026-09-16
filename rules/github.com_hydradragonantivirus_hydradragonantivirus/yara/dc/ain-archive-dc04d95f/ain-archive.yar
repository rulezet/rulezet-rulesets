import "pe"
rule _AIN_Archive_
{
	meta:
		description = "AIN Archive"
	strings:
		$0 = {21 12 00}
		$1 = {21 11 00}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}