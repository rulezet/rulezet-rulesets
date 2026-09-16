rule VirTool_Win32_Obfuscator_VC_2{
	meta:
		description = "VirTool:Win32/Obfuscator.VC,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b7 44 78 fe 04 80 88 45 f7 [0-20] eb 90 14 8d 45 f0 0f b6 55 f7 32 d3 b9 00 00 00 00 } 		$a_01_1 = {8b 02 3d 92 00 00 c0 7f 2c 74 5c } 	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}