import "pe"
rule _Stones_PE_Encrypter_10_
{
	meta:
		description = "Stone's PE Encrypter 1.0"
	strings:
		$0 = {55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 63 3A 40 00 2B 95 C2 3A 40 00 83 EA 0B 89 95 CB 3A 40 00 8D B5 CA 3A 40 00 0F B6 36 8B FD 8D 9D CB 3A 40 00 8B 1B 8D 87 CF 3A 40 00 8B 00 03 D8 8D 8F D3 3A 40 00 8B 09 80 2B 01 43 E2 FA 83 C7}
	condition:
		$0 at pe.entry_point
}