rule TrojanDownloader_Win32_Cutwail_AP_2{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.AP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 08 00 00 "
		
	strings :
		$a_03_0 = {0f b6 1b 81 f3 ?? ?? ?? ?? 81 fb } 		$a_01_1 = {25 00 00 ff ff 05 00 30 00 00 } 		$a_01_2 = {8b c0 ff 73 50 } 		$a_01_3 = {6a 00 e2 fc } 		$a_01_4 = {31 03 83 c3 04 } 		$a_01_5 = {66 b8 01 10 57 5f 66 48 66 81 3a 4d 5a } 		$a_01_6 = {be 93 a2 88 91 97 8c af 81 9d } 		$a_01_7 = {f2 df ee c1 c4 dc cd da fc c7 c3 cd c6 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2) >=3
 
}