rule VirTool_Win32_Feline_A_MTB{
	meta:
		description = "VirTool:Win32/Feline.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {78 63 2f 73 65 72 76 65 72 2e 28 2a 61 75 67 57 72 69 74 65 72 29 2e 57 72 69 74 65 } 		$a_01_1 = {78 63 2f 73 65 72 76 65 72 2e 6c 66 77 64 } 		$a_01_2 = {78 63 2f 73 65 72 76 65 72 2e 68 61 6e 64 6c 65 43 6d 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}