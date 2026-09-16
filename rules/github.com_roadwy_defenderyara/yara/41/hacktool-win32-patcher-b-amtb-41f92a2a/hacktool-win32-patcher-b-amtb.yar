rule HackTool_Win32_Patcher_B_AMTB{
	meta:
		description = "HackTool:Win32/Patcher.B!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_80_0 = {2e 2e 2d 3d 3e 20 43 72 61 63 6b 20 49 6e 66 6f 20 3c 3d 2e 2e } 		$a_80_1 = {43 4f 4e 47 52 41 54 55 4c 41 54 49 4f 4e } 		$a_80_2 = {2e 5f 5f 5f 2e 2e 2d 3d 5b 20 20 54 68 65 20 48 69 76 65 20 20 5d 3d 2d 2e 2e 5f 5f 5f 2e } 		$a_80_3 = {47 50 4d 2d 58 4d 2d 37 35 34 36 37 38 } 		$a_80_4 = {46 69 6c 65 20 53 75 63 63 65 73 66 75 6c 6c 79 20 70 61 74 63 68 65 64 } 		$a_80_5 = {25 73 2e 42 41 4b } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*1) >=7
 
}