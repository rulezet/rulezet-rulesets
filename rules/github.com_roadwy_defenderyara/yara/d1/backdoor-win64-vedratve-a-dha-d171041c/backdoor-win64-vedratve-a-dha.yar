rule Backdoor_Win64_Vedratve_A_dha{
	meta:
		description = "Backdoor:Win64/Vedratve.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {74 65 81 38 44 22 33 11 75 54 83 78 04 01 48 8b c8 75 36 } 		$a_01_1 = {48 89 8c 24 70 02 00 00 85 ff 74 3d 8b 56 08 48 83 64 24 20 00 4c 8d 84 24 70 02 00 00 48 03 d0 4d 8b cc 48 8b cb ff 15 } 		$a_01_2 = {80 7c 19 ed 33 75 37 80 7c 19 ee c0 75 30 80 7c 19 ef 48 75 29 } 		$a_01_3 = {80 7c 19 f0 8d 75 22 80 7c 19 f1 0d 75 1b 80 7c 19 f6 c7 } 		$a_01_4 = {80 7c 19 d7 c5 75 37 80 7c 19 d8 0f 75 30 } 		$a_01_5 = {80 7c 19 d9 84 75 29 80 7c 19 de 48 75 22 80 7c 19 df 8d 75 1b } 	condition:
		((#a_01_0  & 1)*8+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=12
 
}