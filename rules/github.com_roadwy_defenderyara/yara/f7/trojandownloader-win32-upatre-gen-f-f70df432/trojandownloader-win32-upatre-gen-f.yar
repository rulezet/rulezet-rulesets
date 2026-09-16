rule TrojanDownloader_Win32_Upatre_gen_F{
	meta:
		description = "TrojanDownloader:Win32/Upatre.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_01_0 = {57 ff 55 6c 85 c0 75 0d 6a 01 68 e8 03 00 00 ff 55 50 4e 75 eb } 		$a_01_1 = {ff 55 78 33 f6 56 56 56 6a 00 6a 0a b9 06 00 00 00 ff 55 78 50 ff 55 3c 85 c0 74 dd } 		$a_01_2 = {ff 55 78 8a cc 51 b9 06 00 00 00 ff 55 78 50 ff 75 10 ff 55 38 59 85 c0 e1 9c } 		$a_01_3 = {85 c0 e1 f2 0f 84 46 ff ff ff b8 00 09 3d 00 } 		$a_01_4 = {57 56 ad 33 c7 5f ab 8b f7 5f 4f 49 75 f2 } 		$a_01_5 = {66 3d 4c 5b 74 38 8b 45 e4 8b c8 8b 55 c4 c1 e0 02 03 d0 8b 02 83 f8 05 0f 87 1b 01 00 00 } 		$a_01_6 = {89 02 51 68 04 29 00 00 b9 0a 00 00 00 ff 55 78 6a 01 68 d0 07 00 00 ff 55 50 e9 c3 fc ff ff } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=3
 
}