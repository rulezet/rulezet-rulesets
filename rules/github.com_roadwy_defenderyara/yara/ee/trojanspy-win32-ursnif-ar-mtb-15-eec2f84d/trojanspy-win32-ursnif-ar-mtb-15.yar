rule TrojanSpy_Win32_Ursnif_AR_MTB_15{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 5c 24 10 8b ea c1 e5 05 2b ee 03 e8 8d 54 6a 1b 8b c2 2b 05 ?? ?? ?? ?? 81 c7 ec 62 76 01 89 3b } 		$a_03_1 = {2b e8 19 15 ?? ?? ?? ?? 89 2d ?? ?? ?? ?? 8b 44 24 14 81 c3 38 d1 9a 01 89 18 } 		$a_01_2 = {0f b7 ef 8b c5 6b c0 2d 8d 4c 1a 43 8b 5c 24 14 8b 1b 03 c6 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}