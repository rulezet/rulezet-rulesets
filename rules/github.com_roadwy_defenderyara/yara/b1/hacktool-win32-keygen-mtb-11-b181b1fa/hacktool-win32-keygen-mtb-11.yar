rule HackTool_Win32_Keygen_MTB_11{
	meta:
		description = "HackTool:Win32/Keygen.MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {6b 65 79 67 65 6e 2e 65 78 65 } 		$a_80_1 = {43 6f 6e 74 61 69 6e 73 4b 65 79 } 		$a_80_2 = {4b 65 79 6d 61 6b 65 72 } 		$a_80_3 = {48 65 6c 70 4b 65 79 77 6f 72 64 41 74 74 72 69 62 75 74 65 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}