rule Trojan_Win64_Duqu2_H__2{
	meta:
		description = "Trojan:Win64/Duqu2.H!!Duqu2.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 09 48 83 c0 02 66 39 28 75 f7 c7 00 5c 00 4e 00 c7 40 04 54 00 44 00 b9 4c 00 4c 00 } 		$a_01_1 = {66 c7 03 48 b8 4c 89 73 02 4c 8d 4c 24 40 44 8d 47 70 8b d7 48 8b ce 66 c7 43 0a ff e0 ff 55 28 } 		$a_01_2 = {74 22 80 3e 4c 75 0b 48 8d 4e 03 80 39 b8 48 0f 44 f1 2b de c6 06 e9 b8 01 00 00 00 83 eb 05 89 5e 01 eb 02 } 		$a_01_3 = {0f b7 01 b9 ab 4f 5e cd 33 c1 3d e6 15 5e cd 0f 85 8d 00 00 00 } 		$a_01_4 = {43 8b 94 01 88 00 00 00 33 c1 49 03 d0 3d fb 0a 5e cd } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}