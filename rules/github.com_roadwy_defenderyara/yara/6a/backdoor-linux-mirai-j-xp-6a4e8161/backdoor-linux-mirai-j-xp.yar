rule Backdoor_Linux_Mirai_J_xp{
	meta:
		description = "Backdoor:Linux/Mirai.J!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {6d 69 72 61 69 4d 49 52 41 49 } 		$a_00_1 = {73 74 64 66 6c 6f 6f 64 } 		$a_00_2 = {43 30 4e 4e 33 43 54 33 44 } 		$a_00_3 = {56 53 7a 4e 43 30 43 4a 74 69 33 6f 75 6b 75 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}