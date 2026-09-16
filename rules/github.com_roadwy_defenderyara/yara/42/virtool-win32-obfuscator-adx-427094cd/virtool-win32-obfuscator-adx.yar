rule VirTool_Win32_Obfuscator_ADX{
	meta:
		description = "VirTool:Win32/Obfuscator.ADX,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 8f c0 00 00 00 00 01 00 00 e9 16 00 00 00 c7 46 1c c2 00 00 00 81 a7 c0 00 00 00 ff fe ff ff } 		$a_03_1 = {0f b6 03 3c eb 0f 85 1c 00 00 00 0f b6 43 01 0f ba f0 07 0f 83 05 00 00 00 (2d 80 00 00 00|05 80 ff ff ff) 8d 44 03 02 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}