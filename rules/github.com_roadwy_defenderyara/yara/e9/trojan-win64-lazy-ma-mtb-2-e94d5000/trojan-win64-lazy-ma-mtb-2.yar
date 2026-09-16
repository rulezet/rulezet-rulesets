rule Trojan_Win64_Lazy_MA_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 05 00 00 "
		
	strings :
		$a_01_0 = {e9 3d 03 00 00 5b eb 01 45 41 5f eb 01 69 41 5e eb 01 22 41 5d eb 02 19 5a 41 5c eb 03 a0 a0 fd 5e eb 03 0d 23 a5 5f eb 02 65 72 fe 05 3b 04 00 00 eb 03 } 		$a_01_1 = {4d 5a ef 08 d9 94 7f b3 d9 3f 5f 6b 4a c6 e4 9f 35 8d 93 55 01 79 cd 41 e5 00 6e 53 a5 81 2d c3 67 60 90 8c 0a ab 9e d5 45 70 69 b0 ab bf 5f 3a } 		$a_01_2 = {50 61 74 68 4d 61 6b 65 55 6e 69 71 75 65 4e 61 6d 65 } 		$a_01_3 = {52 65 67 4f 70 65 6e 4b 65 79 45 78 57 } 		$a_01_4 = {57 61 69 74 4d 65 73 73 61 67 65 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=26
 
}