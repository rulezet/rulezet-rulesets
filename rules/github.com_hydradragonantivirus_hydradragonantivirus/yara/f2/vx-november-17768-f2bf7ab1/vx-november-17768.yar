import "pe"
rule _Vx_November_17768_
{
	meta:
		description = "Vx: November 17.768"
	strings:
		$0 = {E8 ?? ?? 5E 81 EE ?? ?? 50 33 C0 8E D8 80 3E ?? ?? ?? 0E 1F ?? ?? FC}
	condition:
		$0 at pe.entry_point
}