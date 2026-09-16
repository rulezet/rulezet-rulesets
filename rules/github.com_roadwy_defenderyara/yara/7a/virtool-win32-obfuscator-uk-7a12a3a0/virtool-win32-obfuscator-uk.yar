rule VirTool_Win32_Obfuscator_UK{
	meta:
		description = "VirTool:Win32/Obfuscator.UK,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {55 8b ec be 83 8c 01 00 68 80 0c 0e 00 56 4e 56 68 d0 1f 40 00 c3 } 		$a_01_1 = {65 3a 5c 73 72 63 5c 66 63 72 79 70 74 5c 52 65 6c 65 61 73 65 5c 53 5c 73 5f 68 69 67 68 2e 70 64 62 00 } 		$a_00_2 = {ba 17 c3 05 00 81 c7 6e 03 00 00 2b ca 81 c2 04 7e 02 00 42 2d 77 71 08 00 c2 6c 02 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}