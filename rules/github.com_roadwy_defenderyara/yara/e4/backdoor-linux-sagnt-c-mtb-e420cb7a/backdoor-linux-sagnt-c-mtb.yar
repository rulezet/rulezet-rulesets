rule Backdoor_Linux_SAgnt_C_MTB{
	meta:
		description = "Backdoor:Linux/SAgnt.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 69 45 21 21 21 } 		$a_01_1 = {63 62 5f 73 68 65 6c 6c } 		$a_01_2 = {73 70 61 6d 64 } 		$a_01_3 = {2f 64 65 76 2f 70 74 6d 78 } 		$a_01_4 = {57 65 6c 63 6f 6d 65 20 74 6f 20 6d 79 20 62 61 63 6b 64 6f 6f 72 20 61 63 63 65 73 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}