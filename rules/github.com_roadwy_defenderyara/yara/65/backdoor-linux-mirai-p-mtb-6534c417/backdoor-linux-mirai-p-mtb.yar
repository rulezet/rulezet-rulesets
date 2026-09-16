rule Backdoor_Linux_Mirai_P_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.P!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {54 53 6f 75 72 63 65 20 45 6e 67 69 6e 65 20 51 75 65 72 79 } 		$a_00_1 = {68 74 74 70 66 6c 6f 6f 64 } 		$a_01_2 = {6c 6f 6c 6e 6f 67 74 66 6f } 		$a_00_3 = {75 64 70 70 6c 61 69 6e } 		$a_00_4 = {37 75 6a 4d 6b 6f 30 61 64 6d 69 6e } 		$a_00_5 = {68 75 6e 74 35 37 35 39 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}