rule Backdoor_BAT_Bladabindi_B_2{
	meta:
		description = "Backdoor:BAT/Bladabindi.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 44 4c 56 00 6e 00 47 54 56 00 53 54 56 00 74 00 69 6e 66 00 46 52 00 45 4e 42 00 73 00 44 45 42 00 52 4e 00 63 00 53 42 00 53 00 42 53 00 42 00 66 78 00 } 		$a_01_1 = {00 70 72 00 53 65 6e 64 00 52 43 00 55 4e 53 00 } 		$a_01_2 = {00 5a 49 50 00 43 4d 00 43 61 6d 00 41 43 54 00 48 57 44 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}