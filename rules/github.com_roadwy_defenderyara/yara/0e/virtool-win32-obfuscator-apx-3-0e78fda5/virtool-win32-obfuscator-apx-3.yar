rule VirTool_Win32_Obfuscator_APX_3{
	meta:
		description = "VirTool:Win32/Obfuscator.APX,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 54 24 0c 52 6a 40 [0-18] 51 c7 44 24 1c 40 00 00 00 ff d0 } 		$a_03_1 = {2b f6 81 c6 ?? ?? 00 00 81 ef 90 1b 00 00 00 46 } 	condition:
		((#a_03_0  & 1)*9+(#a_03_1  & 1)*1) >=10
 
}