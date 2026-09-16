rule Backdoor_Linux_Gafgyt_AS_xp_2{
	meta:
		description = "Backdoor:Linux/Gafgyt.AS!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {62 51 5a 75 51 5a 73 51 5a 79 51 5a 62 51 5a 6f 51 5a 78 } 		$a_00_1 = {2f 51 5a 64 51 5a 65 51 5a 76 51 5a 2f 51 5a 6e 51 5a 65 51 5a 74 51 5a 73 51 5a 6c 51 5a 69 51 5a 6e 51 5a 6b 51 5a 2f } 		$a_00_2 = {4b 51 5a 49 51 5a 4c 51 5a 4c } 		$a_00_3 = {55 51 5a 44 51 5a 50 } 		$a_00_4 = {4c 51 5a 49 51 5a 4c 51 5a 42 51 5a 49 51 5a 54 51 5a 43 51 5a 48 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}