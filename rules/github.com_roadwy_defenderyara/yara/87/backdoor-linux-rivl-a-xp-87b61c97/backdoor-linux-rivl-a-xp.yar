rule Backdoor_Linux_Rivl_A_xp{
	meta:
		description = "Backdoor:Linux/Rivl.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 72 69 76 6c 3a } 		$a_01_1 = {73 79 6e 73 70 6f 6f 66 66 6c 6f 6f 64 } 		$a_01_2 = {75 70 64 61 74 65 62 6f 74 73 } 		$a_01_3 = {74 63 70 72 65 6a 65 63 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}