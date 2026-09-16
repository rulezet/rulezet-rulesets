rule Backdoor_Linux_Mirai_BJ_xp_2{
	meta:
		description = "Backdoor:Linux/Mirai.BJ!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 62 6f 74 20 70 72 6f 63 20 73 74 61 72 74 69 6e 67 2e 2e 2e } 		$a_01_1 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 } 		$a_01_2 = {68 6c 4c 6a 7a 74 71 5a } 		$a_01_3 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}