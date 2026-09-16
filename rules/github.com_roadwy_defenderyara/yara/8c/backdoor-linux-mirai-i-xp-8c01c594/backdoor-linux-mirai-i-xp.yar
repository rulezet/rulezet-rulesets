rule Backdoor_Linux_Mirai_I_xp{
	meta:
		description = "Backdoor:Linux/Mirai.I!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_00_0 = {62 6f 74 73 31 2e 66 69 72 65 77 61 6c 6c 61 31 33 33 37 2e 63 63 } 		$a_00_1 = {2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a } 		$a_00_2 = {73 63 61 6e 31 2e 66 69 72 65 77 61 6c 6c 61 31 33 33 37 2e 63 63 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*3+(#a_00_2  & 1)*1) >=5
 
}