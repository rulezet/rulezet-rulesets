rule Backdoor_Linux_Mirai_D_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,0d 00 0d 00 08 00 00 "
		
	strings :
		$a_00_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 43 4f 52 4f 4e 41 } 		$a_00_1 = {ae 39 2e e0 02 30 23 e0 22 c4 23 e0 ff 10 0c e2 2c 28 a0 e1 2c 34 a0 e1 00 00 51 e3 7f 00 51 13 ff 60 02 e2 ff 00 03 e2 2c 2c a0 e1 } 		$a_00_2 = {68 75 6e 74 35 37 35 39 } 		$a_00_3 = {74 73 67 6f 69 6e 67 6f 6e } 		$a_00_4 = {78 6d 68 64 69 70 63 } 		$a_00_5 = {73 79 6e 6e 65 74 } 		$a_00_6 = {65 70 69 63 72 6f 75 74 65 } 		$a_00_7 = {74 65 6c 65 63 6f 6d 61 64 6d 69 6e } 	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=13
 
}