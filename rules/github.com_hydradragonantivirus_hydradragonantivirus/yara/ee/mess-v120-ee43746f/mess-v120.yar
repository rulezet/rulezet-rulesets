import "pe"
rule _MESS_v120_
{
	meta:
		description = "MESS v1.20"
	strings:
		$0 = {FA B9 ?? ?? F3 ?? ?? E3 ?? EB ?? EB ?? B6}
	condition:
		$0 at pe.entry_point
}