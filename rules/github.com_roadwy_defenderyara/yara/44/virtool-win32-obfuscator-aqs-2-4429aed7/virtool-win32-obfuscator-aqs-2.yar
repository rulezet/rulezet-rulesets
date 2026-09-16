rule VirTool_Win32_Obfuscator_AQS_2{
	meta:
		description = "VirTool:Win32/Obfuscator.AQS,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 3d 00 b0 02 10 4d 74 47 66 0f 6f 0d e0 01 02 10 33 c0 f3 0f 6f 80 00 b0 02 10 66 0f ef c1 f3 0f 7f 80 00 b0 02 10 f3 0f 6f 80 00 b0 02 10 66 0f f8 c1 f3 0f 7f 80 00 b0 02 10 83 c0 10 3d 00 2c 00 00 } 		$a_01_1 = {81 3d 0c dc 02 10 c5 19 00 00 0f 44 c2 a2 bc ed 02 10 8b 16 8b c2 c1 e8 1e 83 e0 01 8d 0c 48 8b c2 c1 e8 1f 8d 04 48 8b 7c 85 dc f7 c2 00 00 00 04 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}