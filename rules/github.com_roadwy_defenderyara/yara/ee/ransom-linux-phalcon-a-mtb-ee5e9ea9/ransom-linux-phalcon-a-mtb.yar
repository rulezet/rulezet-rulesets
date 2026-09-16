rule Ransom_Linux_Phalcon_A_MTB{
	meta:
		description = "Ransom:Linux/Phalcon.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 68 61 6c 63 6f 6e } 		$a_01_1 = {2f 74 6d 70 2f 73 74 6f 70 61 6c 6c 2e 73 68 } 		$a_01_2 = {6e 65 75 74 72 69 6e 6f 5f 72 65 73 74 6f 72 65 2e 74 78 74 } 		$a_01_3 = {2d 70 61 74 68 20 2f 70 61 74 68 2f 74 6f 2f 65 6e 63 72 79 70 74 } 		$a_01_4 = {64 72 6f 70 5f 6e 6f 74 65 } 		$a_01_5 = {65 6e 63 72 79 70 74 5f 66 69 6c 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}