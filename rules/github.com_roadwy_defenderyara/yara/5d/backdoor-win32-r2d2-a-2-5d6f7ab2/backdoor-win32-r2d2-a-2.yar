rule Backdoor_Win32_R2d2_A_2{
	meta:
		description = "Backdoor:Win32/R2d2.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {1b c0 25 da ff f2 ff 05 3f 00 0f 00 50 6a 00 51 52 ff 15 } 		$a_01_1 = {1b c9 8d 44 24 04 81 e1 da ff f2 ff 50 8b 44 24 10 56 81 c1 3f 00 0f 00 6a 00 51 6a 00 6a 00 6a 00 52 50 ff 15 } 		$a_01_2 = {44 55 4d 4d 59 21 44 55 4d 4d 59 00 } 		$a_01_3 = {6d 73 6e 6d 73 67 72 2e 65 78 65 } 		$a_01_4 = {53 6b 79 70 65 50 4d 2e 65 78 65 } 		$a_01_5 = {79 61 68 6f 6f 6d 65 73 73 65 6e 67 65 72 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=12
 
}