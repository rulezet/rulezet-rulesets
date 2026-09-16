import "pe"
rule _RCryptor_20__Vaska_
{
	meta:
		description = "RCryptor 2.0 -> Vaska"
	strings:
		$0 = {F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 ?? ?? ?? ?? F7 D1 83 F1 FF}
	condition:
		$0 at pe.entry_point
}