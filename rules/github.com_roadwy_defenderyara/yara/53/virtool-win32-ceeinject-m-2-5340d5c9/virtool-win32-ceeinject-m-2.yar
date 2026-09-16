rule VirTool_Win32_CeeInject_M_2{
	meta:
		description = "VirTool:Win32/CeeInject.M,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {75 f4 8b 15 38 d7 41 00 8b 0d 3c d7 41 00 89 10 8b 15 40 d7 41 00 89 48 04 66 8b 0d 44 d7 41 00 89 50 08 8b 15 a4 63 42 00 52 66 89 48 0c 8d 84 24 20 03 00 00 68 48 d7 41 00 50 } 		$a_01_1 = {00 00 6c 00 7a 00 2e 00 64 00 6c 00 6c 00 } 		$a_01_2 = {00 00 6c 00 72 00 69 00 2e 00 64 00 6c 00 6c 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}