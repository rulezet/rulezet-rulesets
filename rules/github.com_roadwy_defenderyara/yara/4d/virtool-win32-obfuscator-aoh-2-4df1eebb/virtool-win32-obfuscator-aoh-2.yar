rule VirTool_Win32_Obfuscator_AOH_2{
	meta:
		description = "VirTool:Win32/Obfuscator.AOH,SIGNATURE_TYPE_PEHSTR_EXT,06 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b f9 79 0c dd 05 ?? ?? ?? ?? dd 05 ?? ?? ?? ?? d9 c1 d8 e1 d8 c1 d8 c1 d8 c1 d8 e1 d8 c1 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}