rule Trojan_Win64_Vidar_ARR_MTB_3{
	meta:
		description = "Trojan:Win64/Vidar.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f 57 c9 f2 48 0f 2a c9 f2 0f 59 c8 f2 0f 10 15 ?? ?? ?? ?? f2 0f 59 ca f2 0f 11 8c c4 } 		$a_01_1 = {48 8d 0c 89 0f 57 d2 f2 48 0f 2a d1 f2 0f 58 c2 48 ff c0 48 83 f8 } 		$a_81_2 = {6d 61 69 6e 2e 6d 61 69 6e 2e 66 75 6e 63 34 2e 6d 61 69 6e 2e 66 75 6e 63 34 2e 31 34 2e 32 33 2e 31 30 } 		$a_81_3 = {6d 61 69 6e 2e 6d 61 69 6e 2e 66 75 6e 63 31 2e 6d 61 69 6e 2e 66 75 6e 63 31 2e 31 34 2e 32 33 2e 31 32 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*10+(#a_81_2  & 1)*3+(#a_81_3  & 1)*2) >=20
 
}