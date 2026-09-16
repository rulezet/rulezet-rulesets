rule VirTool_Win32_Moteum_A_MTB_4{
	meta:
		description = "VirTool:Win32/Moteum.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {70 6f 73 74 65 78 2e 58 6f 72 69 66 79 } 		$a_01_1 = {70 6f 73 74 65 78 2d 74 6f 6f 6c 73 2f 73 72 63 2f 78 6f 72 74 6f 6f 6c 2f 78 6f 72 74 6f 6f 6c 2e 67 6f } 		$a_01_2 = {70 6f 73 74 65 78 2d 74 6f 6f 6c 73 2f 73 72 63 2f 70 6f 73 74 65 78 2f 78 6f 72 2e 67 6f } 		$a_01_3 = {68 74 74 70 2f 73 6f 63 6b 73 5f 62 75 6e 64 6c 65 2e 67 6f } 		$a_01_4 = {70 6f 73 74 65 78 2f 78 6f 72 2e 67 6f } 		$a_01_5 = {74 6f 6f 6c 73 2f 78 6f 72 74 6f 6f 6c 2e 67 6f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}