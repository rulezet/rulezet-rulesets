rule VirTool_Win32_Moteum_A_MTB_2{
	meta:
		description = "VirTool:Win32/Moteum.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 6f 73 74 65 78 2e 53 74 61 72 74 53 4f 43 4b 53 50 72 6f 78 79 } 		$a_01_1 = {70 6f 73 74 65 78 2e 68 61 6e 64 6c 65 53 4f 43 4b 53 } 		$a_01_2 = {70 6f 73 74 65 78 2e 68 61 6e 64 6c 65 53 4f 43 4b 53 43 6f 6e 6e 65 63 74 69 6f 6e } 		$a_01_3 = {70 6f 73 74 65 78 2e 68 61 6e 64 6c 65 53 4f 43 4b 53 43 6f 6d 6d 75 6e 69 63 61 74 69 6f 6e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}