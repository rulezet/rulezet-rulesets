rule Trojan_Win32_Redline_MG_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 05 00 00 "
		
	strings :
		$a_01_0 = {3b df 03 f1 e9 79 80 17 00 8b 0e 8b 56 04 f7 d1 c1 d8 dc f5 f7 d2 0f a4 d8 71 c0 ec 7e f5 0b ca 66 90 89 4e 04 66 0f b6 c1 9c 80 d4 2d 8f 06 c0 } 		$a_01_1 = {85 f5 33 c3 f9 f8 d1 c8 2d 56 0f b0 1c f8 35 61 45 9b 7f 48 f7 c6 2c 70 d2 5d 35 16 68 93 4b e9 ef 0c 15 00 8b 0e 36 8b 11 0f b7 c4 03 c0 89 16 } 		$a_01_2 = {e0 00 02 01 0b 01 0e 18 00 72 02 00 00 08 09 00 00 00 00 00 10 87 38 00 00 10 } 		$a_01_3 = {2e 76 6d 70 30 } 		$a_01_4 = {2e 76 6d 70 32 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=19
 
}