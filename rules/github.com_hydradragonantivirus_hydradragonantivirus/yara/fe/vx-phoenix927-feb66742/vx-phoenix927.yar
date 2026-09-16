import "pe"
rule _Vx_Phoenix927_
{
	meta:
		description = "Vx: Phoenix.927"
	strings:
		$0 = {E8 00 00 5E 81 C6 ?? ?? BF 00 01 B9 04 00 F3 A4 E8}
	condition:
		$0 at pe.entry_point
}