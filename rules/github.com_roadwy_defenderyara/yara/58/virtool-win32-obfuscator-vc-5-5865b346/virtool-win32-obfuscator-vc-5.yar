rule VirTool_Win32_Obfuscator_VC_5{
	meta:
		description = "VirTool:Win32/Obfuscator.VC,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {0d 00 ff ff ff 40 8a 90 90 ?? ?? ?? ?? 30 14 1e a1 ?? ?? ?? ?? 46 3b f0 72 8b a1 ?? ?? ?? ?? 6a 00 6a 00 6a 03 6a 00 6a 03 68 00 00 00 80 } 		$a_02_1 = {8a 04 2a 33 d2 8a d3 03 d6 03 c2 25 ff 00 00 00 8b f0 8a 86 ?? ?? ?? ?? 88 81 ?? ?? ?? ?? 41 81 f9 00 01 00 00 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}