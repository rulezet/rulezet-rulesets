rule VirTool_Win32_Obfuscator_NV_2{
	meta:
		description = "VirTool:Win32/Obfuscator.NV,SIGNATURE_TYPE_PEHSTR,03 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 85 4c f6 ff ff 2e c6 85 4d f6 ff ff 64 c6 85 4e f6 ff ff 65 c6 85 4f f6 ff ff 72 } 		$a_01_1 = {ac d2 c8 aa 81 c1 15 cd 5b 07 4a 0b d2 75 f1 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}