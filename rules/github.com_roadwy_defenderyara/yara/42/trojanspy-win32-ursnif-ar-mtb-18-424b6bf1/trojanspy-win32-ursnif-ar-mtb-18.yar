rule TrojanSpy_Win32_Ursnif_AR_MTB_18{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_00_0 = {8b 4d f0 83 c1 01 89 4d f0 8b 55 f4 81 c2 74 80 00 00 0f b6 45 eb 2b d0 88 55 eb } 		$a_02_1 = {81 c1 94 ce 08 01 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 f0 a1 ?? ?? ?? ?? 89 82 50 eb ff ff 8b 4d f4 83 e9 46 } 		$a_02_2 = {8b 54 24 10 05 cc 31 06 01 89 02 66 8b 35 ?? ?? ?? ?? a3 ?? ?? ?? ?? bb 48 5f 01 00 b8 c9 1a 00 00 2b d9 } 		$a_02_3 = {8b 7c 24 10 8d 44 0e fd 81 c2 a8 c0 03 01 0f b7 c0 89 17 0f b7 f8 89 15 ?? ?? ?? ?? 8d 74 3e 05 } 		$a_02_4 = {81 c3 88 ea 42 01 89 9c 2e ce ef ff ff 8b 3d ?? ?? ?? ?? 0f b7 f2 8d ?? 46 7e 00 00 8d 04 56 03 c2 39 3d } 		$a_02_5 = {8b 54 24 10 05 c4 d1 01 01 89 02 81 3d ?? ?? ?? ?? 67 07 00 00 a3 ?? ?? ?? ?? 0f b6 c3 75 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1) >=1
 
}