rule VirTool_BAT_Mythagent_B{
	meta:
		description = "VirTool:BAT/Mythagent.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 70 6f 6c 6c 6f 2e 4d 61 6e 61 67 65 6d 65 6e 74 2e 43 32 } 		$a_01_1 = {41 70 6f 6c 6c 6f 2e 50 65 65 72 73 2e 53 4d 42 } 		$a_01_2 = {47 65 74 4d 79 74 68 69 63 55 55 49 44 } 		$a_01_3 = {41 70 6f 6c 6c 6f 2e 50 65 65 72 73 2e 54 43 50 } 		$a_01_4 = {6d 79 74 68 69 63 46 69 6c 65 49 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}