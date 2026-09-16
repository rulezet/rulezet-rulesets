rule HackTool_Win32_Keygen_MTB_3{
	meta:
		description = "HackTool:Win32/Keygen!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {47 65 6e 65 72 61 74 65 } 		$a_80_1 = {6b 65 79 67 65 6e 6e 65 64 20 62 79 20 69 63 65 2f 42 52 44 } 		$a_80_2 = {2d 20 4b 65 79 67 65 6e 20 62 79 20 42 52 44 } 		$a_80_3 = {62 6c 61 63 6b 20 72 69 64 65 72 73 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}