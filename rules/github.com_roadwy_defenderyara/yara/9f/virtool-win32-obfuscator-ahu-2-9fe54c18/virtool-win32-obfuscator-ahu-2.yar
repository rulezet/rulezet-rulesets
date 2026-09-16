rule VirTool_Win32_Obfuscator_AHU_2{
	meta:
		description = "VirTool:Win32/Obfuscator.AHU,SIGNATURE_TYPE_PEHSTR,02 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {bb 12 56 19 00 fc 81 c3 fa 0f 00 00 43 33 d2 f7 e3 05 5f ec 6e 3c 90 fc 90 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}