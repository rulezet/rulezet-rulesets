rule Backdoor_Linux_Gafgyt_E{
	meta:
		description = "Backdoor:Linux/Gafgyt.E,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_80_0 = {6b 65 6b 73 65 63 2e 77 61 73 2e 68 65 72 65 } 		$a_80_1 = {79 6f 75 20 68 61 76 65 20 62 65 65 6e 20 69 6e 66 65 63 74 65 64 20 62 79 } 		$a_80_2 = {6b 6e 6f 77 6e 42 6f 74 73 } 		$a_80_3 = {2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 2f 78 33 38 2f 78 46 4a 2f 78 39 33 2f 78 49 44 2f 78 39 41 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=2
 
}