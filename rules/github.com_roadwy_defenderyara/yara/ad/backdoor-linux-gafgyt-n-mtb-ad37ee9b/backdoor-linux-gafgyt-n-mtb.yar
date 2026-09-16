rule Backdoor_Linux_Gafgyt_N_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.N!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {42 30 54 4b 31 4c 4c } 		$a_01_1 = {54 43 50 2d 52 41 57 } 		$a_01_2 = {68 6c 4c 6a 7a 74 71 4a } 		$a_01_3 = {52 41 57 2d 41 43 4b } 		$a_01_4 = {55 44 50 2d 43 48 45 43 4b 2d 49 50 50 52 4f 54 4f 5f 55 44 50 } 		$a_01_5 = {55 44 50 2d 52 45 47 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}