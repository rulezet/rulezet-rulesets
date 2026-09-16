rule Backdoor_Win32_Conpee_A_2{
	meta:
		description = "Backdoor:Win32/Conpee.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {70 65 65 72 5f 70 6c 75 67 69 6e 5f (6d 61 69 6e|63 6f 6d 6d 61 6e 64) 00 } 		$a_01_1 = {3c 72 65 6d 6f 74 65 66 69 6c 65 3e 20 3c 6c 6f 63 61 6c 66 69 6c 65 3e } 		$a_01_2 = {50 6c 75 67 4d 67 72 5f 52 65 67 69 73 74 65 72 43 6f 6d 6d 61 6e 64 } 		$a_01_3 = {69 69 73 67 65 74 64 69 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}