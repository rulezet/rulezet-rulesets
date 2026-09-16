rule Backdoor_BAT_Uosteil_A{
	meta:
		description = "Backdoor:BAT/Uosteil.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {6b 65 79 6c 6f 67 67 65 72 61 63 74 69 76 65 } 		$a_01_1 = {50 65 72 73 69 73 74 65 6e 63 65 } 		$a_01_2 = {73 74 65 61 6c 66 69 72 65 66 6f 78 } 		$a_01_3 = {64 6f 77 6e 6c 6f 61 64 61 6e 64 65 78 65 63 75 74 65 } 		$a_01_4 = {4d 65 6c 74 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}