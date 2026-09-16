rule HackTool_Win32_Patcher_AMTB{
	meta:
		description = "HackTool:Win32/Patcher!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 69 61 4c 6f 67 2a 65 7a 74 } 		$a_01_1 = {78 78 50 7a 72 67 6d 7a } 		$a_01_2 = {4e 47 20 50 72 61 63 6b 77 3e 34 49 64 40 2d } 		$a_80_3 = {55 6e 69 6e 73 74 2e 65 78 65 } 		$a_80_4 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } 		$a_80_5 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_80_3  & 1)*-100+(#a_80_4  & 1)*-100+(#a_80_5  & 1)*-100) >=3
 
}