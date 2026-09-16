rule VirTool_Win32_Obfuscator_APX_2{
	meta:
		description = "VirTool:Win32/Obfuscator.APX,SIGNATURE_TYPE_PEHSTR_EXT,06 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {32 5c 0a 05 83 c1 06 88 58 05 83 c0 06 81 f9 ?? ?? ?? ?? 0f 8c } 		$a_01_1 = {84 c9 74 0c fe c1 88 08 8a 48 01 40 84 c9 75 f4 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}