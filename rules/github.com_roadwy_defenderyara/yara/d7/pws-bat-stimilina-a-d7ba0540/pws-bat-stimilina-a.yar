rule PWS_BAT_Stimilina_A{
	meta:
		description = "PWS:BAT/Stimilina.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 76 00 64 00 66 00 } 		$a_00_1 = {73 00 74 00 65 00 61 00 6c 00 } 		$a_80_2 = {73 73 66 6e 2a } 		$a_00_3 = {73 00 6d 00 74 00 70 00 2e 00 6d 00 61 00 69 00 6c 00 2e 00 72 00 75 00 } 	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_80_2  & 1)*5+(#a_00_3  & 1)*4) >=11
 
}