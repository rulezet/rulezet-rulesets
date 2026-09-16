rule VirTool_Win32_Obfuscator_ALA{
	meta:
		description = "VirTool:Win32/Obfuscator.ALA,SIGNATURE_TYPE_PEHSTR_EXT,32 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {ff ff 98 7f ff 79 } 		$a_03_1 = {25 ff ff 00 00 0f b7 c0 25 ff 00 00 00 0f b6 c0 8b [0-05] 0f be [0-05] 33 c8 8b [0-05] 88 [0-05] 8b [0-05] d1 e8 89 [0-05] 8b [0-05] 0f be [0-05] 8b [0-05] 41 89 [0-05] 85 c0 75 } 		$a_01_2 = {f3 a9 94 9d 9c 90 cd cd 51 db b3 83 f7 00 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*5+(#a_01_2  & 1)*2) >=8
 
}