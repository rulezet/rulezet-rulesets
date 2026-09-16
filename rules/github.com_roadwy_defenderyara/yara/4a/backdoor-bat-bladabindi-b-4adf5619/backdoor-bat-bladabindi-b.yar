rule Backdoor_BAT_Bladabindi_B{
	meta:
		description = "Backdoor:BAT/Bladabindi.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {00 57 4c 00 44 4c 56 00 6e 00 } 		$a_01_1 = {00 47 65 74 4b 65 79 00 6b 65 79 00 70 72 00 } 		$a_01_2 = {00 66 78 00 62 00 73 70 6c 00 5a 49 50 00 43 4d 00 } 		$a_01_3 = {00 53 42 00 53 00 42 53 00 42 00 } 		$a_01_4 = {00 57 52 4b 00 55 53 42 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}