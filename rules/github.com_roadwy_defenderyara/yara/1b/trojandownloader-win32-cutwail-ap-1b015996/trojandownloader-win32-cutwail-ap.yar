rule TrojanDownloader_Win32_Cutwail_AP{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.AP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {80 38 4d 75 1f 80 78 01 5a 75 19 } 		$a_01_1 = {6a 19 33 d2 59 f7 f1 80 c2 61 eb 13 3c 58 } 		$a_01_2 = {66 83 7e 06 00 8d 7c 30 18 76 31 83 c7 14 } 		$a_01_3 = {80 78 50 69 } 		$a_01_4 = {80 78 51 7a 0f 94 c1 8b c1 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}