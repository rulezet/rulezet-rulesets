rule HackTool_Win32_Keygen_AMTB_3{
	meta:
		description = "HackTool:Win32/Keygen!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_80_0 = {6c 64 72 5f 6b 65 79 67 65 6e } 		$a_80_1 = {57 68 79 20 73 6f 20 73 65 72 69 6f 75 73 3f 21 } 		$a_80_2 = {4c 69 6e 65 5a 65 72 30 } 		$a_80_3 = {4c 7a 30 20 32 6f 6f 39 } 		$a_80_4 = {41 20 50 72 6f 64 75 63 74 20 62 79 20 4c 7a 30 } 	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=15
 
}