rule HackTool_Win32_Gamehack_G_MSR{
	meta:
		description = "HackTool:Win32/Gamehack.G!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 6f 75 6c 64 6e 27 74 20 66 69 6e 64 20 63 73 67 6f 2e 65 78 65 21 } 		$a_01_1 = {6a 75 73 74 47 6c 6f 77 2e 70 64 62 } 		$a_01_2 = {47 4c 4f 57 48 41 43 4b 3a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}