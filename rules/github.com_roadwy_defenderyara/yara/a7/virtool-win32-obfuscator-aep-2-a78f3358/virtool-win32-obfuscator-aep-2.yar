rule VirTool_Win32_Obfuscator_AEP_2{
	meta:
		description = "VirTool:Win32/Obfuscator.AEP,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 ea 89 2c ?? 83 c1 04 81 (c2|ea) ?? ?? ?? ?? 40 81 f9 ?? ?? ?? ?? 7c } 		$a_03_1 = {33 fa 89 3c ?? 83 c1 04 81 (c2|ea) ?? ?? ?? ?? 40 81 f9 ?? ?? ?? ?? 7c } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*2) >=12
 
}