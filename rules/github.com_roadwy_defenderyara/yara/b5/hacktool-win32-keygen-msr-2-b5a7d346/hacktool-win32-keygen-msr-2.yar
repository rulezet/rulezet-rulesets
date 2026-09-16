rule HackTool_Win32_Keygen_MSR_2{
	meta:
		description = "HackTool:Win32/Keygen!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {41 43 4b 4e 4f 57 4c 45 44 47 45 20 2d 42 52 4b 2d } 		$a_80_1 = {47 65 6e 65 72 61 74 65 } 		$a_80_2 = {6e 6f 72 77 69 63 68 2e 6e 65 74 } 		$a_80_3 = {4b 65 79 67 65 6e } 		$a_80_4 = {42 4b 54 2f 42 52 44 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}