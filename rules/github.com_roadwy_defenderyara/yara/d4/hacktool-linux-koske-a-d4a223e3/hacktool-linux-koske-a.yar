rule HackTool_Linux_Koske_A{
	meta:
		description = "HackTool:Linux/Koske.A,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 69 64 65 70 72 6f 63 2e 73 6f } 		$a_01_1 = {6b 6f 73 6b 65 } 		$a_01_2 = {2f 64 65 76 2f 73 68 6d 2f 2e 68 69 64 64 65 6e 70 69 64 } 		$a_01_3 = {2f 70 72 6f 63 2f 73 65 6c 66 2f 66 64 2f 25 64 } 		$a_01_4 = {64 6c 73 79 6d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}