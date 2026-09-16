rule TrojanSpy_Win32_Ursnif_AR_MTB_17{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_02_0 = {03 de 81 c1 a4 92 51 01 0f b7 f0 89 0d ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 89 0a 8b 0d ?? ?? ?? ?? 8b c6 83 c7 04 8d 44 08 0b a3 ?? ?? ?? ?? 81 ff 8a 15 00 00 0f 82 } 		$a_02_1 = {05 44 f4 01 01 89 44 24 18 89 01 b9 ff ff 00 00 a3 ?? ?? ?? ?? 69 c3 1d 5a 00 00 2b c8 2b ce 0f af ca } 		$a_02_2 = {8b 44 24 10 81 c7 94 2d c9 01 89 bc 28 7f fc ff ff 8a 15 ?? ?? ?? ?? 0f b6 ea bb 59 00 00 00 81 fd cc 18 00 00 75 } 		$a_00_3 = {81 c6 24 a9 91 01 8d 84 10 f9 82 fe ff 89 b4 39 64 da ff ff 8d 4c 00 04 8b e9 2b eb 83 c7 04 8d 44 28 c9 81 ff 6c 26 00 00 0f } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=1
 
}