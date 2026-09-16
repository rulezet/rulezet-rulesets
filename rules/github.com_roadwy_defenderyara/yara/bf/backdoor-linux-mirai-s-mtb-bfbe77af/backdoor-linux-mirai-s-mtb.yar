rule Backdoor_Linux_Mirai_S_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.S!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {75 64 70 68 65 78 } 		$a_00_1 = {74 63 70 72 61 6e 64 } 		$a_00_2 = {75 64 70 72 61 6e 64 } 		$a_00_3 = {62 79 70 61 73 73 } 		$a_00_4 = {74 63 70 70 6c 61 69 6e } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}