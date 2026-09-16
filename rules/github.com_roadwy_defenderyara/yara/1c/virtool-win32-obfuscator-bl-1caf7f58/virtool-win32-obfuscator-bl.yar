rule VirTool_Win32_Obfuscator_BL{
	meta:
		description = "VirTool:Win32/Obfuscator.BL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {0f be c1 8a 4a 01 33 c6 42 84 c9 75 ?? 5e c2 04 00 } 		$a_00_1 = {68 34 33 32 31 54 } 		$a_00_2 = {6a 01 68 44 33 22 11 b8 dd cc bb aa ff d0 c3 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}