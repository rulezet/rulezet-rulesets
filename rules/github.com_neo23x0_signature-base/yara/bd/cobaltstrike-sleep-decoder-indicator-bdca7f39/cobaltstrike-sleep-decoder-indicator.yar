rule CobaltStrike_Sleep_Decoder_Indicator {
	meta:
		description = "Detects CobaltStrike sleep_mask decoder"
		author = "yara@s3c.za.net"
		date = "2021-07-19"
		id = "d5b53d68-55f9-5837-9b0c-e7be2f3bd072"
	strings:
		$sleep_decoder = { 48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 4C 8B 51 08 41 8B F0 48 8B EA 48 8B D9 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 }
	condition:
		$sleep_decoder
}