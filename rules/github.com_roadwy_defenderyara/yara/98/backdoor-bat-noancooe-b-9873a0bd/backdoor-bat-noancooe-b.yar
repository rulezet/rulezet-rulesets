rule Backdoor_BAT_Noancooe_B{
	meta:
		description = "Backdoor:BAT/Noancooe.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4e 61 6e 6f 43 6f 72 65 2e 43 6c 69 65 6e 74 50 6c 75 67 69 6e 00 } 		$a_01_1 = {43 6f 6e 6e 65 63 74 69 6f 6e 53 74 61 74 65 43 68 61 6e 67 65 64 00 } 		$a_01_2 = {53 65 6e 64 54 6f 53 65 72 76 65 72 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}