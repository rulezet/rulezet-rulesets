rule HackTool_Win32_Keygen_MTB_4{
	meta:
		description = "HackTool:Win32/Keygen!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_80_0 = {54 45 41 4d 20 46 46 46 } 		$a_80_1 = {72 61 72 72 65 67 2e 6b 65 79 } 		$a_80_2 = {6b 65 79 67 65 6e } 		$a_80_3 = {42 55 54 54 4f 4e 42 4f 58 57 49 4e 44 4f 57 } 		$a_00_4 = {6b 65 6e 74 70 77 40 6e 6f 72 77 69 63 68 2e 6e 65 74 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}