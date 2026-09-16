import "pe"
rule _Mew_10_execoder_10___Northfox_HCC_
{
	meta:
		description = "Mew 10 exe-coder 1.0  -> Northfox [HCC]"
	strings:
		$0 = {33 C0 E9 ?? ?? FF FF 6A ?? ?? ?? ?? ?? 70}
	condition:
		$0 at pe.entry_point
}