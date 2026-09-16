rule Backdoor_BAT_Noancooe_A_2{
	meta:
		description = "Backdoor:BAT/Noancooe.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4e 61 6e 6f 43 6f 72 65 2e 65 78 65 } 		$a_01_1 = {4c 56 5f 47 52 4f 55 50 00 48 65 61 64 65 72 73 00 42 61 73 65 43 6f 6d 6d 61 6e 64 00 } 		$a_01_2 = {42 72 6f 6e 7a 65 00 53 69 6c 76 65 72 00 47 6f 6c 64 00 50 6c 61 74 69 6e 75 6d 00 44 69 61 6d 6f 6e 64 00 } 		$a_01_3 = {13 0e 11 0e 16 1f 58 9d 11 0e 17 1f 30 9d 11 0e 18 1f 58 9d 11 0e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}