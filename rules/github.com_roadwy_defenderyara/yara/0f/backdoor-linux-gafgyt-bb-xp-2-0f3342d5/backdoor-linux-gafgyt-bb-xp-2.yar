rule Backdoor_Linux_Gafgyt_BB_xp_2{
	meta:
		description = "Backdoor:Linux/Gafgyt.BB!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 6d 20 2d 72 66 20 43 68 65 61 74 73 2a } 		$a_00_1 = {63 64 20 2f 72 6f 6f 74 } 		$a_01_2 = {4d 6f 6a 65 65 6b 42 6f 74 2f 32 2e 30 } 		$a_00_3 = {2f 65 74 63 2f 72 65 73 6f 6c 76 2e 63 6f 6e 66 } 		$a_01_4 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}