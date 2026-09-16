rule VirTool_Win32_CeeInject_TN_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TN!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8a 4d 13 8a 10 32 d1 02 d1 88 10 40 89 45 08 } 		$a_01_1 = {03 cf 8b f8 8b d1 c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 } 		$a_01_2 = {8a c1 3c 61 7c 06 3c 7a 7f 02 24 df c3 } 		$a_01_3 = {8b 07 8b c8 8b d0 c1 e9 1d c1 ea 1e 8b f0 83 e1 01 83 e2 01 c1 ee 1f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}