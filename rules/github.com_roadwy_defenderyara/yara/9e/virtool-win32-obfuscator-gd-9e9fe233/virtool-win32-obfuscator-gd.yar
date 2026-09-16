rule VirTool_Win32_Obfuscator_GD{
	meta:
		description = "VirTool:Win32/Obfuscator.GD,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 85 04 f8 ff ff } 		$a_01_1 = {8b 85 08 f8 ff ff } 		$a_01_2 = {3d 88 77 00 00 e9 } 		$a_01_3 = {3d ba 77 00 00 0f 83 } 		$a_01_4 = {3d 82 78 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}