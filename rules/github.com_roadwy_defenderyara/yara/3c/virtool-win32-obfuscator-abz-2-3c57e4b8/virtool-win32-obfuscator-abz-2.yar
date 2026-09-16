rule VirTool_Win32_Obfuscator_ABZ_2{
	meta:
		description = "VirTool:Win32/Obfuscator.ABZ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {60 33 c0 f7 f0 61 } 		$a_03_1 = {51 ff 75 dc c7 85 ?? fc ff ff 07 00 01 00 ff d0 85 c0 0f 88 } 		$a_03_2 = {8b 41 3c 03 45 fc 8d ?? 08 f8 00 00 00 8b ?? 0c 03 45 f8 89 45 cc 8b ?? 08 } 		$a_03_3 = {2a 16 30 14 08 ?? 75 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}