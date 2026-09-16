rule Backdoor_Linux_Mirai_JX_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.JX!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 74 74 61 63 6b 73 5f 73 74 6f 6d 70 } 		$a_01_1 = {6b 69 6c 6c 65 72 5f 76 61 6e 69 73 68 5f 6c 69 73 74 } 		$a_01_2 = {61 74 74 61 63 6b 73 5f 69 63 6d 70 } 		$a_01_3 = {74 63 70 5f 6b 69 6c 6c 5f 70 6f 72 74 } 		$a_01_4 = {6b 69 6c 6c 65 72 5f 73 68 6f 6f 74 5f 6c 69 73 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}