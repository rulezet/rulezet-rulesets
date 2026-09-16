rule PWS_BAT_Stimilina_C{
	meta:
		description = "PWS:BAT/Stimilina.C,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 00 67 00 61 00 74 00 65 00 5f 00 6e 00 65 00 77 00 2e 00 70 00 68 00 70 00 } 		$a_80_1 = {73 73 66 6e 2a } 		$a_01_2 = {53 74 65 61 6d 53 74 65 61 6c 65 72 } 		$a_01_3 = {53 74 65 61 6d 57 6f 72 6b 65 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_80_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3) >=10
 
}