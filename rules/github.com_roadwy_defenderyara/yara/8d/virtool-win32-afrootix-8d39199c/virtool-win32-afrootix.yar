rule VirTool_Win32_Afrootix{
	meta:
		description = "VirTool:Win32/Afrootix,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 3d a0 57 41 00 00 74 2b 68 18 37 41 00 a1 a0 57 41 00 50 e8 93 0f ff ff 8b f0 89 f3 85 f6 74 13 6a 00 b9 a4 57 41 00 ba f0 2e 41 00 8b c6 e8 64 b5 ff ff } 		$a_01_1 = {4e 74 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } 		$a_01_2 = {6e 65 74 73 74 61 74 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}