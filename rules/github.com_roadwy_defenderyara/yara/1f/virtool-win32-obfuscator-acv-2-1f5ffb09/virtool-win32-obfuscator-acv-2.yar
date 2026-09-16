rule VirTool_Win32_Obfuscator_ACV_2{
	meta:
		description = "VirTool:Win32/Obfuscator.ACV,SIGNATURE_TYPE_PEHSTR_EXT,64 00 0b 00 06 00 00 "
		
	strings :
		$a_01_0 = {be 77 05 00 00 } 		$a_01_1 = {bb 77 05 00 00 } 		$a_01_2 = {bf 77 05 00 00 } 		$a_01_3 = {b9 77 05 00 00 } 		$a_03_4 = {77 05 00 00 90 09 06 00 c7 85 } 		$a_01_5 = {4a 3a 5c 38 37 35 36 6a 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*10) >=11
 
}