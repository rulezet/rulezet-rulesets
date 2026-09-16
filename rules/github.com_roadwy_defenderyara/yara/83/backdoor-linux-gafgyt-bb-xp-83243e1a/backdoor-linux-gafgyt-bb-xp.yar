rule Backdoor_Linux_Gafgyt_BB_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.BB!xp,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 75 73 72 2f 73 62 69 6e 2f 64 72 6f 70 62 65 61 72 } 		$a_03_1 = {77 67 65 74 20 68 74 74 70 3a 2f 2f [0-20] 2f 62 69 6e 73 2e 73 68 } 		$a_01_2 = {68 6c 4c 6a 7a 74 71 5a } 		$a_01_3 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}