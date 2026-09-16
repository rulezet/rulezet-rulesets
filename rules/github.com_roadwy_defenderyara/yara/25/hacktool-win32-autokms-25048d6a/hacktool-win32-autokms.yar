rule HackTool_Win32_AutoKMS{
	meta:
		description = "HackTool:Win32/AutoKMS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {6f 65 6d 2d 64 72 76 38 36 2e 70 64 62 } 		$a_80_1 = {53 79 73 74 65 6d 52 6f 6f 74 5c 73 79 73 74 65 6d 33 32 5c 44 52 49 56 45 52 53 5c 6f 65 6d 2d 64 72 76 38 36 2e 73 79 73 } 		$a_80_2 = {73 65 63 72 39 74 6f 73 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}