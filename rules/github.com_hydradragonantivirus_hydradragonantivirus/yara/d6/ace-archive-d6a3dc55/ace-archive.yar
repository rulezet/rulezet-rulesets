import "pe"
rule _ACE_Archive_
{
	meta:
		description = "ACE Archive"
	strings:
		$0 = {2A 2A 41 43 45 2A 2A}
	condition:
		$0 at pe.entry_point
}