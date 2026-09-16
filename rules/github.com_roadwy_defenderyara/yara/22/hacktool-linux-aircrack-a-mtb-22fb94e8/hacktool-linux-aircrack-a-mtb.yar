rule HackTool_Linux_AirCrack_A_MTB{
	meta:
		description = "HackTool:Linux/AirCrack.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {61 69 72 63 72 61 63 6b 2d 6e 67 } 		$a_00_1 = {6c 69 62 2f 63 65 2d 77 65 70 2f 75 6e 69 71 75 65 69 76 2e 63 } 		$a_01_2 = {77 65 70 2d 64 65 63 6c 6f 61 6b } 		$a_01_3 = {50 54 57 5f 6e 65 77 61 74 74 61 63 6b 73 74 61 74 65 28 29 } 		$a_01_4 = {70 74 77 2d 64 65 62 75 67 } 		$a_00_5 = {61 69 72 63 72 61 63 6b 2d 63 65 2d 77 70 61 } 	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}