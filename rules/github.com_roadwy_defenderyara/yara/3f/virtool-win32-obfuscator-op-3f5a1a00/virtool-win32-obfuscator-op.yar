rule VirTool_Win32_Obfuscator_OP{
	meta:
		description = "VirTool:Win32/Obfuscator.OP,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {eb 00 c6 05 ?? ?? ?? ?? ?? c6 05 ?? ?? ?? ?? ?? c6 05 } 		$a_01_1 = {eb 00 0f b6 d1 81 f2 } 		$a_03_2 = {eb 00 8b 15 ?? ?? ?? ?? 33 55 08 89 55 0c 0f b6 45 18 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}