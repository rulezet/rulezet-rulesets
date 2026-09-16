rule VirTool_Win32_Obfuscator_PV_2{
	meta:
		description = "VirTool:Win32/Obfuscator.PV,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b cc 8d 61 ?? 59 } 		$a_03_1 = {8b c4 8d 60 ?? 58 } 		$a_01_2 = {81 38 33 c0 c2 08 0f 84 } 		$a_03_3 = {81 38 8b ff 90 90 33 0f 84 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}