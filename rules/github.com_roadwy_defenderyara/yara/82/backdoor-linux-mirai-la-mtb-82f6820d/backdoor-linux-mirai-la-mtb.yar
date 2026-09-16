rule Backdoor_Linux_Mirai_LA_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.LA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 74 74 61 63 6b 41 64 64 48 6f 73 74 } 		$a_01_1 = {4b 69 6c 6c 65 72 53 63 61 6e 50 69 64 73 } 		$a_01_2 = {41 74 74 61 63 6b 54 63 70 48 61 6e 64 73 68 61 6b 65 } 		$a_01_3 = {41 74 74 61 63 6b 54 63 70 41 63 6b } 		$a_01_4 = {41 74 74 61 63 6b 47 72 65 45 74 68 47 62 70 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}