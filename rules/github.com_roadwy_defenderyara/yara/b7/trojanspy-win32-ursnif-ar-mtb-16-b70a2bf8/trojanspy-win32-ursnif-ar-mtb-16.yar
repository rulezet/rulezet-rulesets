rule TrojanSpy_Win32_Ursnif_AR_MTB_16{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_00_0 = {83 44 24 10 04 0f b7 d0 2b d7 81 c2 2b ec 00 00 ff 4c 24 14 0f 85 } 		$a_02_1 = {8b 54 24 10 81 c7 dc 9e 6c 01 89 3a 0f b6 15 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 0f b6 3d ?? ?? ?? ?? 2b fa 81 ff ?? ?? ?? ?? 75 } 		$a_02_2 = {89 0a 0f b6 0d ?? ?? ?? ?? 81 f9 c5 6e 02 00 0f b7 c0 89 44 24 10 75 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}