rule HackTool_Win32_Keygen_3{
	meta:
		description = "HackTool:Win32/Keygen,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_80_0 = {54 45 41 4d 20 5a 57 54 } 		$a_80_1 = {59 6f 75 20 68 61 76 65 20 62 65 65 6e 20 74 72 61 63 65 64 } 		$a_80_2 = {4b 65 79 6d 61 6b 65 72 20 66 6f 72 } 		$a_80_3 = {26 47 65 6e 65 72 61 74 65 } 		$a_80_4 = {26 51 75 69 74 } 	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=6
 
}