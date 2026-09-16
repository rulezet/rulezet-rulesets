rule HackTool_Win32_Keygen_MTB_2{
	meta:
		description = "HackTool:Win32/Keygen!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {54 72 65 65 41 67 65 20 50 72 6f 20 53 75 69 74 65 } 		$a_80_1 = {4b 65 79 47 65 6e 65 72 61 74 6f 72 } 		$a_80_2 = {53 65 72 69 61 6c 20 4e 75 6d 62 65 72 } 		$a_80_3 = {47 65 6e 65 72 61 74 65 } 	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}