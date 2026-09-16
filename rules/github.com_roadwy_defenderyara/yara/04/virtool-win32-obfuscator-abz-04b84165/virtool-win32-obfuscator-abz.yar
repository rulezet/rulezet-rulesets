rule VirTool_Win32_Obfuscator_ABZ{
	meta:
		description = "VirTool:Win32/Obfuscator.ABZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 0a 8d 58 01 0f af de 30 1c 02 40 3b c1 7c f2 } 		$a_01_1 = {75 f1 68 3f 20 00 00 68 c3 06 00 00 68 28 91 40 00 e8 90 ff ff ff 83 c4 0c b8 28 91 40 00 ff d0 33 c0 5b 8b e5 5d c2 10 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}