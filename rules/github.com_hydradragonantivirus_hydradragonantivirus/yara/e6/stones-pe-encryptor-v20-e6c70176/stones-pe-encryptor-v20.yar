import "pe"
rule _Stones_PE_Encryptor_v20_
{
	meta:
		description = "Stone's PE Encryptor v2.0"
	strings:
		$0 = {60 E8 5D 81 ED 06 64 A0}
	condition:
		$0 at pe.entry_point
}