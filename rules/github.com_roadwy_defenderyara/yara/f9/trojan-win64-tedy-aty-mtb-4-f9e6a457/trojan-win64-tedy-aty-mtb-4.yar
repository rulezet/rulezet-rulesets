rule Trojan_Win64_Tedy_ATY_MTB_4{
	meta:
		description = "Trojan:Win64/Tedy.ATY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {39 c6 76 1a 69 d2 0d 66 19 00 81 c2 5f f3 6e 3c 89 d1 c1 e9 18 41 30 0c 04 48 ff c0 } 		$a_01_1 = {8a 14 06 89 d1 83 e2 0f c0 e9 04 41 8a 14 10 0f b6 c9 41 8a 0c 08 88 54 43 01 88 0c 43 48 ff c0 48 83 f8 20 } 		$a_01_2 = {6c 6f 67 69 6e 75 73 65 72 73 2e 76 64 66 } 		$a_01_3 = {64 65 6c 2e 62 61 74 } 	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=10
 
}