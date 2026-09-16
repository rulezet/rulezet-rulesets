rule VirTool_Win32_Obfuscator_AHC_2{
	meta:
		description = "VirTool:Win32/Obfuscator.AHC,SIGNATURE_TYPE_PEHSTR_EXT,32 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 4c 4f 4f 00 } 		$a_01_1 = {75 08 40 3d 00 e9 a4 35 75 d0 66 51 90 90 90 90 90 66 52 90 90 90 90 90 66 b9 5a 60 90 90 90 90 90 90 90 90 90 90 66 8b d1 90 90 90 90 90 e2 fe 90 90 90 90 90 66 8b ca 90 90 90 90 90 e2 e2 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}