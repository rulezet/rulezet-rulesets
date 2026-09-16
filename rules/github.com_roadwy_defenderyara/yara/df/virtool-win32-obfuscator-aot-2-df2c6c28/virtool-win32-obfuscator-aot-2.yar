rule VirTool_Win32_Obfuscator_AOT_2{
	meta:
		description = "VirTool:Win32/Obfuscator.AOT,SIGNATURE_TYPE_PEHSTR_EXT,06 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {85 d2 74 01 46 49 75 f8 [0-14] 8b 1d ?? ?? [40-47] 00 50 52 ff d3 } 		$a_01_1 = {85 f6 74 01 42 49 75 f8 f8 [0-14] 8b 1d ?? ?? [40-47] 00 50 56 ff d7 } 		$a_03_2 = {7e 07 03 f1 41 3b ca 7c f9 [0-30] 81 e2 ff 01 00 00 03 c2 [0-30] ff 15 ?? ?? ?? ?? 50 ff 15 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}