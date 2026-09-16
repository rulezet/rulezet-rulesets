rule VirTool_Win32_Obfuscator_PN{
	meta:
		description = "VirTool:Win32/Obfuscator.PN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {9f ff ff 2b c8 03 4d f8 89 4d f8 8b 45 f8 90 09 02 00 b9 } 		$a_03_1 = {05 00 5a 00 00 [0-10] 33 c7 66 3b 46 20 5f 5e 5b 0f 84 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}