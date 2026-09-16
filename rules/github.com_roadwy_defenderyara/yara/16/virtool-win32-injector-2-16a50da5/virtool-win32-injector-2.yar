rule VirTool_Win32_Injector_2{
	meta:
		description = "VirTool:Win32/Injector,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {b8 6a 12 59 b8 cc cc cc cc f3 ab 59 89 55 f8 89 } 		$a_01_1 = {4d e0 03 48 04 39 4d d0 73 78 8b 4d d0 e8 } 		$a_01_2 = {eb 66 83 65 d0 00 6a 2e 5a 8b 4d c0 e8 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}