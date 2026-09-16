rule Backdoor_Linux_Gafgyt_BE_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.BE!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {6b 69 6c 6c 64 61 62 6f 74 } 		$a_01_1 = {62 6f 74 6b 69 6c 6c } 		$a_01_2 = {62 6f 74 20 2d 75 64 70 } 		$a_01_3 = {73 63 61 6e 6e 65 72 } 		$a_01_4 = {62 6f 74 20 2d 74 63 70 } 		$a_01_5 = {4b 69 6c 6c 69 6e 67 20 70 69 64 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}