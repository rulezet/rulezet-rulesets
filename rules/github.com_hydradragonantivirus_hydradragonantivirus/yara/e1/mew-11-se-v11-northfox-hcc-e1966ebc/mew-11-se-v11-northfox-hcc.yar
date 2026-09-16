import "pe"
rule _MEW_11_SE_v11__Northfox_HCC_
{
	meta:
		description = "MEW 11 SE v1.1 -> Northfox [HCC"
	strings:
		$0 = {E9 ?? ?? ?? FF 0C}
	condition:
		$0 at pe.entry_point
}