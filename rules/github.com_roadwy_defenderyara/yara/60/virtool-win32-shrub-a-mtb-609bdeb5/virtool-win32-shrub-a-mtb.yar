rule VirTool_Win32_Shrub_A_MTB{
	meta:
		description = "VirTool:Win32/Shrub.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {67 6f 72 73 68 2f 69 6e 74 65 72 6e 61 6c 2f 73 73 68 6f 63 6b 73 } 		$a_01_1 = {66 6c 61 74 74 65 6e 66 6c 6f 61 74 33 32 66 6c 6f 61 74 36 34 67 63 74 72 61 63 65 67 6f 72 73 68 } 		$a_01_2 = {67 6f 72 73 68 2e 63 32 } 		$a_01_3 = {48 6f 6c 65 79 53 6f 63 6b 73 2f 70 6b 67 2f 68 6f 6c 65 79 73 6f 63 6b 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}