rule HackTool_Win32_Keygen_AMTB_2{
	meta:
		description = "HackTool:Win32/Keygen!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {43 6f 64 65 64 20 62 79 20 4c 6f 72 64 20 42 6c 69 78 2f 54 53 5a } 		$a_80_1 = {52 65 67 69 73 74 72 61 74 69 6f 6e 20 43 6f 64 65 } 		$a_80_2 = {2d 4b 65 79 67 65 6e 2d } 		$a_80_3 = {47 65 6e 65 72 61 74 65 } 	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}