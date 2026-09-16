import "pe"
rule _DAEMON_Protect_v067_
{
	meta:
		description = "DAEMON Protect v0.6.7"
	strings:
		$0 = {BE 01 40 ?? 6A 05 59 80 7E 07 ?? 74 11 8B}
	condition:
		$0 at pe.entry_point
}