rule VirTool_Win32_Obfuscator_PV_3{
	meta:
		description = "VirTool:Win32/Obfuscator.PV,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {33 c0 c2 08 0f (84|85) } 		$a_03_1 = {8b 45 fc 66 83 78 06 02 0f (84|85) } 		$a_01_2 = {bb 90 90 90 90 } 		$a_03_3 = {39 58 6f 0f (84|85) } 		$a_01_4 = {81 78 05 33 c0 c9 c2 0f } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*2) >=4
 
}