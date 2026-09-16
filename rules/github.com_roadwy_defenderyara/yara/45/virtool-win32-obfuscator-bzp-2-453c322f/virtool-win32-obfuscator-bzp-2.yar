rule VirTool_Win32_Obfuscator_BZP_2{
	meta:
		description = "VirTool:Win32/Obfuscator.BZP,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 ea 00 eb 02 03 fe eb 02 2b f9 68 ?? ?? ?? ?? c3 33 d5 c1 e8 00 8b c0 68 ?? ?? ?? ?? c3 } 		$a_01_1 = {8b 55 f8 33 0a 8b 45 f8 89 08 5f 5e 8b e5 5d c3 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}