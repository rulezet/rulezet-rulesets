rule VirTool_Win32_Moteum_A_MTB{
	meta:
		description = "VirTool:Win32/Moteum.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 6f 73 74 65 78 2e 53 65 6e 64 46 69 6c 65 } 		$a_01_1 = {70 6f 73 74 65 78 2e 52 65 63 76 46 69 6c 65 } 		$a_01_2 = {70 6f 73 74 65 78 2d 74 6f 6f 6c 73 } 		$a_01_3 = {73 79 73 63 61 6c 6c 2f 77 69 6e 64 6f 77 73 2f 7a 73 79 73 63 61 6c 6c 5f 77 69 6e 64 6f 77 73 2e 67 6f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}