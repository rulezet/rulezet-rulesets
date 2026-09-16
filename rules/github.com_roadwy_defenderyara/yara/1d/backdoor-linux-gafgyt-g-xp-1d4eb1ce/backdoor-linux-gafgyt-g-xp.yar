rule Backdoor_Linux_Gafgyt_G_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.G!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {77 67 65 74 20 68 74 74 70 3a 2f 2f 62 61 64 6c 75 63 6b 6a 6f 73 68 2e 70 77 2f 64 6f 6e 67 73 2f 62 6c 6a 2e 73 68 20 7c 7c } 		$a_00_1 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 3b 65 63 68 6f 20 2d 65 20 27 5c 31 34 37 5c 31 34 31 5c 31 37 31 5c 31 34 36 5c 31 34 37 5c 31 36 34 } 		$a_00_2 = {73 65 6e 64 48 4f 4c 44 } 		$a_00_3 = {73 65 6e 64 4a 55 4e 4b } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}