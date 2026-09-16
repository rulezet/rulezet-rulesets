rule VirTool_Win32_Obfuscator_AQS{
	meta:
		description = "VirTool:Win32/Obfuscator.AQS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {51 c3 c3 55 89 e5 83 ec 28 c7 45 ec 00 00 00 00 b9 ?? ?? 1d 02 } 		$a_01_1 = {55 89 e5 c9 c2 10 00 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 } 		$a_01_2 = {55 89 e5 c9 c2 10 00 c3 c3 c3 c3 c3 c3 c3 c3 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}