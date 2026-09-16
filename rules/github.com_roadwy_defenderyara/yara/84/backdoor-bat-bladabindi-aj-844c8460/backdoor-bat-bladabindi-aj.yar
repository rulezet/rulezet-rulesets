rule Backdoor_BAT_Bladabindi_AJ{
	meta:
		description = "Backdoor:BAT/Bladabindi.AJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 4e 74 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 00 6e 74 64 6c 6c 00 } 		$a_01_1 = {00 63 61 70 47 65 74 44 72 69 76 65 72 44 65 73 63 72 69 70 74 69 6f 6e 41 00 61 76 69 63 61 70 33 32 2e 64 6c 6c 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}