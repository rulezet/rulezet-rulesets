rule VirTool_Win32_Obfuscator_PV{
	meta:
		description = "VirTool:Win32/Obfuscator.PV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {81 38 8b ff cc c3 0f 84 } 		$a_03_1 = {81 38 33 c0 c2 ?? 0f 84 } 		$a_01_2 = {32 4c 90 01 c1 e1 08 32 0c 90 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}