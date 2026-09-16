rule Trojan_Win32_Dridex_GD_MTB_4{
	meta:
		description = "Trojan:Win32/Dridex.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 14 00 04 00 00 "
		
	strings :
		$a_02_0 = {0f b6 d8 29 fb 88 d8 88 44 24 ?? 8a 44 24 ?? 8b 7d ?? 8b 5d ?? 88 04 1f } 		$a_80_1 = {76 53 69 6c 76 65 72 72 69 67 68 74 31 38 2c 63 61 70 61 62 69 6c 69 74 69 65 73 70 6f 70 75 6c 61 72 69 74 79 77 69 6e 57 69 6e 64 6f 77 73 54 68 65 69 6c 6f 76 65 79 6f 75 } 		$a_02_2 = {40 cc cc cc eb ?? 8b 04 24 64 a3 00 00 00 00 83 c4 08 eb ?? 8b 44 24 ?? ff 80 ?? ?? ?? ?? 31 c0 c3 c3 } 		$a_80_3 = {74 74 74 74 33 32 } 	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1+(#a_02_2  & 1)*10+(#a_80_3  & 1)*10) >=20
 
}