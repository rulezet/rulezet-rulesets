rule Backdoor_Linux_Gafgyt_ba_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.ba!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 72 61 77 6c 65 72 2e 61 73 70 } 		$a_00_1 = {44 6f 6e 74 20 55 73 65 20 74 68 65 20 54 65 6c 6e 65 74 20 53 63 61 6e 6e 65 72 } 		$a_00_2 = {62 6f 74 6e 65 74 54 53 63 61 6e } 		$a_00_3 = {72 6d 20 2d 72 66 20 2f 74 6d 70 2f 2a 20 2f 76 61 72 2f 2a 20 2f 76 61 72 2f 72 75 6e 2f 2a 20 2f 76 61 72 2f 74 6d 70 2f 2a } 		$a_00_4 = {73 65 6e 64 53 54 44 48 45 58 20 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}