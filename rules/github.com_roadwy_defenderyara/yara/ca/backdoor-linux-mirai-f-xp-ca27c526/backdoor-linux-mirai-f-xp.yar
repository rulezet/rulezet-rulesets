rule Backdoor_Linux_Mirai_F_xp{
	meta:
		description = "Backdoor:Linux/Mirai.F!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 75 72 65 6e 65 74 77 6f 72 6b 73 2e 63 6f 6d 2f 48 4e 41 50 31 2f } 		$a_03_1 = {2f 74 6d 70 [0-11] 68 75 61 77 65 69 2e 65 78 70 6c 6f 69 74 } 		$a_00_2 = {2f 6e 69 67 20 72 65 61 6c 74 65 6b 2e 65 78 70 6c 6f 69 74 } 		$a_00_3 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 37 37 37 20 2a 20 2f 74 6d 70 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}