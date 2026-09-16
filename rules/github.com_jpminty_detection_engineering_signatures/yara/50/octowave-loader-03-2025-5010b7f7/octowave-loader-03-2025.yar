rule Octowave_Loader_03_2025
{
	meta:
        description = "Detects opcodes found in Octowave Loader DLLs and WAV steganography files"
        author = "Jai Minton (@CyberRaiju) - HuntressLabs"
        date = "2025-03-19"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        yt_reference = "https://www.youtube.com/watch?v=NiNIbkiuExU"
        x_reference = "https://x.com/CyberRaiju/status/1893450184224362946?t=u0X6ST2Qgnrf-ujjphGOSg&s=19"
        hash1 = "0504BFBACB6E10B81196F625F2FE37B33500E7BF65FD82D3510A2B178C6CD5BD"
        hash2 = "3A2DB0CB9EE01549A6B660D58115D112D36A744D65705394B54D7D95287C7A74"
        hash3 = "EB50D06057FE123D6E9F7A76D3D1A4BC5307E8F15D017BE8F6031E92136CF36A"
        hash4 = "24715920E749B014BA05F74C96627A27355C5860A14461C106AA48A7ABA371EA"
        shoutout = "https://yaratoolkit.securitybreak.io/"
        id = "84d9f24f-154e-4fef-b6ba-a2e051aa5842"
	
	strings:
		$opcode_1 = {
			55
			8B EC
			56
			57
			8B D1
			33 C0
			8B FA
			6A 06
			59
			AB
			AB
			AB
			AB
			8B 45 08
			8B FA
			83 62 10 00
			8B F0
			83 62 14 00
			F3 A5
			83 60 10 00
		}
	
		$opcode_2 = {
			55
			8B EC
			8B 55 ??
			56
			8B F1
			8B 46 ??
			8B 4E ??
			2B C1
			3B D0
			77 ??
			83 7E ?? 07
			53
			8D 1C 11
			57
			89 5E ??
			8B FE
			76 ??
			8B 3E
			8D 04 12
			50
			FF 75 ??
			8D 0C 4F
			51
			E8 ?? ?? ?? ??
			83 C4 0C
			33 C0
			66 89 04 5F
			8B C6
			5F
			5B
			EB ??
			52
			FF 75 ??
			8B CE
			FF 75 ??
			52
			E8 ?? ?? ?? ??
			5E
			5D
			C2 08 00
		}

	
		$opcode_3 = {
			55
			8B EC
			8B 4D 08
			83 C9 ??
			56
			3B 4D 10
			77 1C
			8B 75 0C
			8B D6
			8B 45 10
			D1 EA
			2B C2
			3B F0
			77 0C
			8D 04 32
			3B C8
			0F 42 C8
			8B C1
			EB 03
		}

	
		$opcode_4 = {
			56
			8B F1
			8B 46 14
			83 F8 ??
			76 ??
		}

		$opcode_5 = {
			50
			FF 36
			E8 ?? ?? ?? ??
			59
			59
			83 66 ?? 00
		}
		$opcode_6 = {
			C7 46 14 ?? 00 00 00
			66 89 06
			5E
			C3
		}

	
		$opcode_7 = {
			55
			8B EC
			51
			51
			A1 ?? ?? ?? ??
			33 C5
			89 45 FC
			8B 4D 0C
			8B 45 08
			89 45 F8
			81 F9 00 10 00 00
			72 ??
			8D 45 0C
			50
			8D 45 F8
			50
			E8 ?? ?? ?? ??
			8B 45 F8
			59
			59
		}

	condition:
		(uint16(0) == (0x5a4d) or uint32(0) ==  0x46464952) 
		and filesize < 50000KB
		and all of them

}