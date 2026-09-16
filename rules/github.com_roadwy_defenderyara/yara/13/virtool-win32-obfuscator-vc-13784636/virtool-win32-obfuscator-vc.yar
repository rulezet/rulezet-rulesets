rule VirTool_Win32_Obfuscator_VC{
	meta:
		description = "VirTool:Win32/Obfuscator.VC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d8 9c 80 0c 24 01 9d 0f 82 90 16 46 9c 80 0c 24 01 9d 0f 82 90 16 8b 83 ?? ?? ?? 00 9c 80 0c 24 01 9d 0f 82 90 16 03 83 ?? ?? ?? 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}