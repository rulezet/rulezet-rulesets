rule VirTool_Win32_Obfuscator_APX{
	meta:
		description = "VirTool:Win32/Obfuscator.APX,SIGNATURE_TYPE_PEHSTR_EXT,06 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 3f 2b d2 81 c2 ?? ?? ?? ?? 2b d2 81 c2 90 1b 00 [0-10] 89 7d fc } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}