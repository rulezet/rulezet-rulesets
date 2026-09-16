import "pe"
rule _Mew_11_SE_v12_Eng__Northfox_
{
	meta:
		description = "Mew 11 SE v1.2 (Eng) -> Northfox"
	strings:
		$0 = {E9 ?? ?? ?? FF 0C ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C}
	condition:
		$0 at pe.entry_point
}