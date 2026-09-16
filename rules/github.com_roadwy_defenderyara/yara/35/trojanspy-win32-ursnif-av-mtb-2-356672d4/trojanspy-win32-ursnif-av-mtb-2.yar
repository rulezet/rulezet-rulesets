rule TrojanSpy_Win32_Ursnif_AV_MTB_2{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_02_0 = {81 c2 98 42 4c 01 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 e4 8b 0d ?? ?? ?? ?? 89 88 36 ed ff ff 0f b7 55 e8 } 		$a_00_1 = {81 c5 24 12 11 01 83 c0 a0 03 f8 8b 44 24 10 89 ac 01 6d f5 ff ff 8d 0c 3f 2b ca 8b 54 24 10 } 		$a_02_2 = {81 c1 e8 8b f2 01 89 0d ?? ?? ?? ?? 02 c3 89 0e 04 02 66 0f b6 c8 66 6b c9 06 66 03 0d } 		$a_02_3 = {81 c2 80 e7 bf 01 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 e4 8b 0d ?? ?? ?? ?? 89 88 ee e1 ff ff 0f b7 55 e8 6b d2 06 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=1
 
}