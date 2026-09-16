rule Backdoor_Win32_Escad_F_dha_2{
	meta:
		description = "Backdoor:Win32/Escad.F!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {80 e2 34 80 c2 2d 88 54 24 10 8b d1 f7 da 1a d2 80 e2 37 80 c2 2d 88 54 24 11 8b d0 80 e2 02 f6 da 1a d2 80 e2 3b 80 c2 2d f7 d9 1a c9 24 04 80 e1 45 88 54 24 12 80 c1 2d } 		$a_01_1 = {25 34 64 2f 25 32 64 2f 25 32 64 5f 25 32 64 3a 25 32 64 } 		$a_01_2 = {25 73 20 25 2d 32 30 73 20 25 31 30 6c 75 20 25 73 } 		$a_01_3 = {5f 71 75 69 74 00 00 00 5f 65 78 65 00 00 00 00 5f 70 75 74 00 00 00 00 5f 67 6f 74 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}