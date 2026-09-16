import "pe"
rule _Exe_Shield_v29_
{
	meta:
		description = "Exe Shield v2.9"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED FB 1D 40 ?? B9 7B 09 ?? ?? 8B F7}
	condition:
		$0 at pe.entry_point
}