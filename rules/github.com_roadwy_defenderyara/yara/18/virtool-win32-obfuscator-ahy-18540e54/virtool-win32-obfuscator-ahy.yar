rule VirTool_Win32_Obfuscator_AHY{
	meta:
		description = "VirTool:Win32/Obfuscator.AHY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 a8 5a 2a b2 66 20 03 be 22 f5 61 66 65 20 7c 1b f7 b8 } 		$a_01_1 = {20 60 18 48 e6 66 66 20 bb e7 b7 19 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}