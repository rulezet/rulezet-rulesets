rule Backdoor_Linux_Mirai_J_xp_2{
	meta:
		description = "Backdoor:Linux/Mirai.J!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_00_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 54 53 55 4e 41 4d 49 } 		$a_00_1 = {63 64 20 2f 3b 20 77 67 65 74 20 68 74 74 70 3a 2f 2f 32 30 39 2e 31 34 31 2e 34 35 2e 31 33 39 2f 73 6f 72 61 2e 73 68 3b } 		$a_00_2 = {5c 78 34 35 5c 78 34 33 5c 78 34 38 5c 78 34 66 5c 78 34 34 5c 78 34 66 5c 78 34 65 5c 78 34 35 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*3) >=5
 
}