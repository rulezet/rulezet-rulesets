import "pe"
rule _Stones_PE_Encryptor_v113_
{
	meta:
		description = "Stone's PE Encryptor v1.13"
	strings:
		$0 = {53 51 52 56 57 55 E8 5D 81 ED 42 30 40 FF 95 32 35 40 B8 37 30 40 03 C5 2B 85 1B 34 40 89 85 27 34 40}
	condition:
		$0 at pe.entry_point
}